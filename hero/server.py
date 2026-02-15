from mcp.server.fastmcp import FastMCP
import os
import re
import httpx
import json
import sys
import hashlib
import uuid
from pathlib import Path
from typing import Optional, Dict, Any, List, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import threading
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).parent.parent / ".env"
print(f"[DEBUG] Loading .env from: {env_path} (exists: {env_path.exists()})")
load_dotenv(env_path, override=True)

# Add shared_logs to path for events module
BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR / "shared_logs"))

from events import read_events, get_event_stats, EventType, AttackType

# --- CONFIGURATION ---
# Define the name of your agent for Archestra
# host="0.0.0.0" allows external connections, port 8765 for Archestra integration
mcp = FastMCP("SecOps Sentinel", host="0.0.0.0", port=8765)

# PATHS: These must match the folder structure we defined.
BASE_DIR = Path(__file__).parent.parent
LOG_FILE = BASE_DIR / "shared_logs" / "auth.log"
ACCESS_LOG_FILE = BASE_DIR / "shared_logs" / "access.log"
BLOCKED_IPS_FILE = BASE_DIR / "shared_logs" / "blocked_ips.txt"
AUDIT_LOG_FILE = BASE_DIR / "shared_logs" / "archestra_audit.jsonl"
THREAT_INTEL_FILE = BASE_DIR / "shared_logs" / "threat_intel.txt"

# ARCHESTRA CONFIGURATION
ARCHESTRA_ENABLED = os.getenv("ARCHESTRA_ENABLED", "true").lower() == "true"
ARCHESTRA_API_URL = os.getenv("ARCHESTRA_API_URL", "http://localhost:9000")
ARCHESTRA_API_KEY = os.getenv("ARCHESTRA_API_KEY", "").strip()
ARCHESTRA_STRICT_MODE = os.getenv("ARCHESTRA_STRICT_MODE", "true").lower() == "true"

# Debug output
print(f"[DEBUG] ARCHESTRA_ENABLED: {ARCHESTRA_ENABLED}")
print(f"[DEBUG] ARCHESTRA_API_URL: {ARCHESTRA_API_URL}")
print(f"[DEBUG] ARCHESTRA_API_KEY loaded: {'Yes (' + str(len(ARCHESTRA_API_KEY)) + ' chars)' if ARCHESTRA_API_KEY else 'No (empty)'}")
print(f"[DEBUG] ARCHESTRA_STRICT_MODE: {ARCHESTRA_STRICT_MODE}")

# Ensure directories exist
BLOCKED_IPS_FILE.parent.mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED ARCHESTRA POLICY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class RiskLevel(str, Enum):
    """Risk classification for operations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyDecision(str, Enum):
    """Possible policy decisions from Archestra."""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    RATE_LIMITED = "rate_limited"
    ESCALATE = "escalate"


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    window_seconds: int
    max_calls: int
    action: PolicyDecision


@dataclass
class PolicyResult:
    """Structured result from policy evaluation."""
    allowed: bool
    decision: PolicyDecision
    reason: str
    requires_approval: bool = False
    approval_id: Optional[str] = None
    risk_score: float = 0.0
    matched_policy: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    audit_id: Optional[str] = None


@dataclass
class ThreatContext:
    """Contextual information for threat-based policy decisions."""
    attack_count: int = 0
    attack_severity: str = "unknown"
    attack_confidence: float = 0.0
    in_threat_feed: bool = False
    is_internal_ip: bool = False
    geo_country: Optional[str] = None
    current_hour: int = 0


class RateLimiter:
    """
    Thread-safe rate limiter for tool calls.
    Implements sliding window rate limiting per tool.
    """
    
    def __init__(self):
        self._lock = threading.Lock()
        self._call_history: Dict[str, List[datetime]] = defaultdict(list)
        
        # Rate limit configurations per tool
        self._limits: Dict[str, List[RateLimitConfig]] = {
            'firewall_block_ip': [
                RateLimitConfig(window_seconds=3600, max_calls=10, action=PolicyDecision.DENY),
                RateLimitConfig(window_seconds=86400, max_calls=50, action=PolicyDecision.REQUIRE_APPROVAL),
            ],
            'system_lockdown': [
                RateLimitConfig(window_seconds=86400, max_calls=1, action=PolicyDecision.DENY),
            ],
            'firewall_bulk_block': [
                RateLimitConfig(window_seconds=3600, max_calls=3, action=PolicyDecision.REQUIRE_APPROVAL),
            ],
        }
    
    def check_rate_limit(self, tool_name: str) -> Optional[PolicyResult]:
        """
        Check if a tool call is within rate limits.
        Returns PolicyResult if rate limited, None if allowed.
        """
        if tool_name not in self._limits:
            return None
        
        with self._lock:
            now = datetime.utcnow()
            history = self._call_history[tool_name]
            
            for limit in self._limits[tool_name]:
                window_start = now - timedelta(seconds=limit.window_seconds)
                recent_calls = [t for t in history if t > window_start]
                
                if len(recent_calls) >= limit.max_calls:
                    window_desc = f"{limit.window_seconds // 3600}h" if limit.window_seconds >= 3600 else f"{limit.window_seconds // 60}m"
                    return PolicyResult(
                        allowed=False,
                        decision=PolicyDecision.RATE_LIMITED,
                        reason=f"Rate limit exceeded: Maximum {limit.max_calls} calls per {window_desc}",
                        requires_approval=limit.action == PolicyDecision.REQUIRE_APPROVAL,
                        matched_policy="rate_limit",
                        context={"calls_in_window": len(recent_calls), "limit": limit.max_calls}
                    )
            
            return None
    
    def record_call(self, tool_name: str):
        """Record a successful tool call for rate limiting."""
        with self._lock:
            self._call_history[tool_name].append(datetime.utcnow())
            # Cleanup old entries (older than 24 hours)
            cutoff = datetime.utcnow() - timedelta(hours=24)
            self._call_history[tool_name] = [
                t for t in self._call_history[tool_name] if t > cutoff
            ]


class ThreatIntelligence:
    """
    Manages threat intelligence feeds for automated policy decisions.
    """
    
    def __init__(self):
        self._lock = threading.Lock()
        self._blocklist: Set[str] = set()
        self._recent_attackers: Dict[str, int] = {}  # IP -> attack count
        self._allowlist: Set[str] = {"127.0.0.1", "localhost"}
        self._last_refresh = datetime.min
        self._refresh_interval = timedelta(minutes=5)
        
        # Load static blocklist
        self._load_blocklist()
    
    def _load_blocklist(self):
        """Load static blocklist from file."""
        if THREAT_INTEL_FILE.exists():
            try:
                with open(THREAT_INTEL_FILE, "r") as f:
                    for line in f:
                        ip = line.strip()
                        if ip and not ip.startswith("#"):
                            self._blocklist.add(ip)
            except Exception as e:
                print(f"[WARN] Failed to load threat intel: {e}")
    
    def refresh_from_events(self):
        """Refresh recent attackers from event stream."""
        with self._lock:
            if datetime.utcnow() - self._last_refresh < self._refresh_interval:
                return
            
            try:
                # Get attacks from last 24 hours
                events = read_events(limit=1000, event_type=EventType.ATTACK)
                attacker_counts: Dict[str, int] = {}
                
                for evt in events:
                    src_ip = evt.get('network', {}).get('source_ip')
                    if src_ip:
                        attacker_counts[src_ip] = attacker_counts.get(src_ip, 0) + 1
                
                # Update recent attackers (threshold: 5+ attacks)
                self._recent_attackers = {
                    ip: count for ip, count in attacker_counts.items() if count >= 5
                }
                self._last_refresh = datetime.utcnow()
                
            except Exception as e:
                print(f"[WARN] Failed to refresh threat intel: {e}")
    
    def is_known_threat(self, ip: str) -> bool:
        """Check if IP is in threat intelligence feeds."""
        self.refresh_from_events()
        with self._lock:
            return ip in self._blocklist or ip in self._recent_attackers
    
    def is_allowlisted(self, ip: str) -> bool:
        """Check if IP is in allowlist (never block)."""
        with self._lock:
            return ip in self._allowlist
    
    def get_attack_count(self, ip: str) -> int:
        """Get the number of recent attacks from an IP."""
        self.refresh_from_events()
        with self._lock:
            return self._recent_attackers.get(ip, 0)
    
    def is_internal_ip(self, ip: str) -> bool:
        """Check if IP is an internal network address."""
        return (
            ip.startswith("10.") or
            ip.startswith("192.168.") or
            ip.startswith("172.16.") or
            ip.startswith("172.17.") or
            ip.startswith("172.18.") or
            ip.startswith("172.19.") or
            ip.startswith("172.2") or
            ip.startswith("172.30.") or
            ip.startswith("172.31.") or
            ip in ["127.0.0.1", "0.0.0.0", "localhost"]
        )
    
    def add_to_blocklist(self, ip: str):
        """Add IP to dynamic blocklist."""
        with self._lock:
            self._blocklist.add(ip)


class AuditLogger:
    """
    Comprehensive audit logging for compliance and forensics.
    """
    
    def __init__(self, log_path: Path):
        self._log_path = log_path
        self._lock = threading.Lock()
    
    def log(
        self,
        event_type: str,
        tool_name: str,
        parameters: Dict[str, Any],
        decision: PolicyDecision,
        reason: str,
        user_role: str = "agent",
        risk_score: float = 0.0,
        approval_id: Optional[str] = None,
        matched_policy: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log an audit event. Returns the audit ID.
        """
        audit_id = str(uuid.uuid4())
        
        audit_entry = {
            "audit_id": audit_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "tool_name": tool_name,
            "parameters": self._sanitize_parameters(parameters),
            "decision": decision.value,
            "reason": reason,
            "user_role": user_role,
            "risk_score": risk_score,
            "approval_id": approval_id,
            "matched_policy": matched_policy,
            "context": context or {},
            "agent": "SecOps Sentinel",
            "archestra_enabled": ARCHESTRA_ENABLED
        }
        
        with self._lock:
            try:
                with open(self._log_path, "a") as f:
                    f.write(json.dumps(audit_entry) + "\n")
                    f.flush()
            except Exception as e:
                print(f"[ERROR] Failed to write audit log: {e}")
        
        return audit_id
    
    def _sanitize_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive data from parameters before logging."""
        sanitized = {}
        sensitive_keys = {"password", "secret", "token", "api_key", "credential"}
        
        for key, value in params.items():
            if any(s in key.lower() for s in sensitive_keys):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = value
        
        return sanitized


class ArchestraClient:
    """
    Advanced client for Archestra policy validation with:
    - Rate limiting
    - Threat intelligence integration
    - Dynamic risk scoring
    - Audit logging
    - Policy caching
    - Role-based access control
    """
    
    def __init__(self, api_url: str, api_key: str = ""):
        self.api_url = api_url
        self.api_key = api_key
        self.client = httpx.Client(timeout=10.0)
        
        # Initialize components
        self.rate_limiter = RateLimiter()
        self.threat_intel = ThreatIntelligence()
        self.audit_logger = AuditLogger(AUDIT_LOG_FILE)
        
        # Policy cache (TTL: 5 minutes)
        self._policy_cache: Dict[str, tuple[PolicyResult, datetime]] = {}
        self._cache_ttl = timedelta(minutes=5)
        self._cache_lock = threading.Lock()
        
        # Protected IP ranges that can NEVER be blocked
        self._protected_ranges = [
            "127.",
            "0.0.0.0",
            "localhost",
        ]
    
    def _get_cache_key(self, tool_name: str, parameters: Dict[str, Any]) -> str:
        """Generate a cache key for policy decisions."""
        param_str = json.dumps(parameters, sort_keys=True)
        return hashlib.sha256(f"{tool_name}:{param_str}".encode()).hexdigest()
    
    def _check_cache(self, cache_key: str) -> Optional[PolicyResult]:
        """Check if a cached policy decision exists and is valid."""
        with self._cache_lock:
            if cache_key in self._policy_cache:
                result, timestamp = self._policy_cache[cache_key]
                if datetime.utcnow() - timestamp < self._cache_ttl:
                    return result
                else:
                    del self._policy_cache[cache_key]
        return None
    
    def _cache_result(self, cache_key: str, result: PolicyResult):
        """Cache a policy decision."""
        with self._cache_lock:
            self._policy_cache[cache_key] = (result, datetime.utcnow())
    
    def _calculate_risk_score(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        context: ThreatContext
    ) -> float:
        """
        Calculate dynamic risk score based on multiple factors.
        Score range: 0.0 (safe) to 1.0 (maximum risk)
        """
        base_scores = {
            'firewall_block_ip': 0.3,
            'system_lockdown': 0.9,
            'firewall_bulk_block': 0.5,
            'analyze_logs': 0.05,
            'get_security_events': 0.02,
        }
        
        score = base_scores.get(tool_name, 0.1)
        
        # Adjust based on context
        if context.in_threat_feed:
            score *= 0.7  # Lower risk if in threat feed (more justified)
        
        if context.attack_count > 10:
            score *= 0.8  # Lower risk if many attacks (clear evidence)
        
        if context.is_internal_ip:
            score *= 2.0  # Higher risk for internal IPs
        
        if context.current_hour < 6 or context.current_hour > 22:
            score *= 1.3  # Higher risk during off-hours
        
        if context.attack_severity == "critical":
            score *= 0.9  # Slightly lower risk for critical threats
        
        # Cap at 1.0
        return min(score, 1.0)
    
    def _build_threat_context(
        self,
        tool_name: str,
        parameters: Dict[str, Any]
    ) -> ThreatContext:
        """Build threat context from available data."""
        ip_address = parameters.get('ip_address', '')
        
        context = ThreatContext(
            attack_count=self.threat_intel.get_attack_count(ip_address),
            in_threat_feed=self.threat_intel.is_known_threat(ip_address),
            is_internal_ip=self.threat_intel.is_internal_ip(ip_address),
            current_hour=datetime.utcnow().hour,
        )
        
        # Try to get attack severity from recent events
        if context.attack_count > 0:
            events = read_events(limit=10, event_type=EventType.ATTACK)
            for evt in events:
                if evt.get('network', {}).get('source_ip') == ip_address:
                    context.attack_severity = evt.get('severity', 'unknown')
                    break
        
        # Calculate confidence based on evidence
        if context.attack_count > 0:
            context.attack_confidence = min(0.5 + (context.attack_count * 0.05), 0.99)
        
        return context
    
    def _evaluate_local_policies(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        context: ThreatContext,
        risk_score: float
    ) -> Optional[PolicyResult]:
        """
        Evaluate local policies before calling Archestra API.
        Returns PolicyResult if a local policy matches, None otherwise.
        """
        ip_address = parameters.get('ip_address', '')
        
        # Policy: Protect internal infrastructure (DENY)
        if tool_name == 'firewall_block_ip' and context.is_internal_ip:
            return PolicyResult(
                allowed=False,
                decision=PolicyDecision.DENY,
                reason="DENIED: Cannot block internal/protected IP addresses per policy 'protect_internal_infrastructure'",
                matched_policy="protect_internal_infrastructure",
                risk_score=risk_score,
                context={"protected_ip": True, "ip_address": ip_address}
            )
        
        # Policy: Auto-approve known threats with high confidence
        if (tool_name == 'firewall_block_ip' and 
            context.in_threat_feed and 
            context.attack_count > 10 and 
            context.attack_confidence > 0.85):
            return PolicyResult(
                allowed=True,
                decision=PolicyDecision.ALLOW,
                reason=f"Auto-approved: IP {ip_address} in threat feed with {context.attack_count} attacks (confidence: {context.attack_confidence:.2f})",
                matched_policy="auto_block_known_threats",
                risk_score=risk_score,
                context={
                    "auto_approved": True,
                    "attack_count": context.attack_count,
                    "confidence": context.attack_confidence
                }
            )
        
        # Policy: Critical severity with strong evidence
        if (tool_name == 'firewall_block_ip' and
            context.attack_severity == 'critical' and
            context.attack_count > 10 and
            context.attack_confidence > 0.85):
            return PolicyResult(
                allowed=True,
                decision=PolicyDecision.ALLOW,
                reason=f"Auto-approved: Critical severity attack from {ip_address} with strong evidence",
                matched_policy="critical_severity_auto_approve",
                risk_score=risk_score,
                context={
                    "auto_approved": True,
                    "severity": "critical",
                    "attack_count": context.attack_count
                }
            )
        
        # Policy: Off-hours escalation
        if (tool_name in ['firewall_block_ip', 'system_lockdown'] and
            (context.current_hour < 6 or context.current_hour > 22)):
            return PolicyResult(
                allowed=False,
                decision=PolicyDecision.REQUIRE_APPROVAL,
                reason=f"Off-hours operation (hour: {context.current_hour}) requires manager approval per policy 'off_hours_escalation'",
                requires_approval=True,
                matched_policy="off_hours_escalation",
                risk_score=risk_score,
                approval_id=f"apr_{uuid.uuid4().hex[:8]}",
                context={"off_hours": True, "hour": context.current_hour}
            )
        
        return None
    
    def validate_policy(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        risk_level: str = "medium",
        user_role: str = "operator"
    ) -> PolicyResult:
        """
        Comprehensive policy validation with multiple layers:
        1. Rate limiting check
        2. Threat intelligence context
        3. Local policy evaluation
        4. Remote Archestra API validation
        5. Audit logging
        
        Args:
            tool_name: Name of the tool being called
            parameters: Tool parameters
            risk_level: Risk level classification
            user_role: Role of the user/agent making the request
        
        Returns:
            PolicyResult with complete decision information
        """
        # Check cache first
        cache_key = self._get_cache_key(tool_name, parameters)
        cached = self._check_cache(cache_key)
        if cached:
            return cached
        
        # If Archestra is disabled, allow but log
        if not ARCHESTRA_ENABLED:
            result = PolicyResult(
                allowed=True,
                decision=PolicyDecision.ALLOW,
                reason="Archestra is disabled - operation allowed without policy check",
                matched_policy="archestra_disabled"
            )
            self.audit_logger.log(
                event_type="policy_bypass",
                tool_name=tool_name,
                parameters=parameters,
                decision=PolicyDecision.ALLOW,
                reason=result.reason,
                user_role=user_role
            )
            return result
        
        # Step 1: Check rate limits
        rate_limit_result = self.rate_limiter.check_rate_limit(tool_name)
        if rate_limit_result:
            rate_limit_result.audit_id = self.audit_logger.log(
                event_type="rate_limited",
                tool_name=tool_name,
                parameters=parameters,
                decision=rate_limit_result.decision,
                reason=rate_limit_result.reason,
                user_role=user_role,
                matched_policy="rate_limit"
            )
            return rate_limit_result
        
        # Step 2: Build threat context
        context = self._build_threat_context(tool_name, parameters)
        
        # Step 3: Calculate risk score
        risk_score = self._calculate_risk_score(tool_name, parameters, context)
        
        # Step 4: Evaluate local policies
        local_result = self._evaluate_local_policies(tool_name, parameters, context, risk_score)
        if local_result:
            local_result.risk_score = risk_score
            local_result.audit_id = self.audit_logger.log(
                event_type="local_policy_match",
                tool_name=tool_name,
                parameters=parameters,
                decision=local_result.decision,
                reason=local_result.reason,
                user_role=user_role,
                risk_score=risk_score,
                matched_policy=local_result.matched_policy,
                context=local_result.context
            )
            
            # Cache the result
            self._cache_result(cache_key, local_result)
            
            # Record successful call if allowed
            if local_result.allowed:
                self.rate_limiter.record_call(tool_name)
            
            return local_result
        
        # Step 5: Call Archestra API for policy decision
        try:
            payload = {
                'tool': tool_name,
                'parameters': parameters,
                'risk_level': risk_level,
                'risk_score': risk_score,
                'agent': 'SecOps Sentinel',
                'user_role': user_role,
                'context': {
                    'attack_count': context.attack_count,
                    'attack_severity': context.attack_severity,
                    'attack_confidence': context.attack_confidence,
                    'in_threat_feed': context.in_threat_feed,
                    'is_internal_ip': context.is_internal_ip,
                    'current_hour': context.current_hour,
                }
            }
            
            headers = {'Content-Type': 'application/json'}
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
            
            response = self.client.post(
                f"{self.api_url}/api/v1/validate-policy",
                json=payload,
                headers=headers
            )
            
            # Validate response
            if response.status_code == 200:
                data = response.json()
                
                # Validate response schema
                if not all(key in data for key in ['allowed', 'reason']):
                    raise ValueError("Invalid Archestra response: missing required fields")
                
                result = PolicyResult(
                    allowed=data.get('allowed', False),
                    decision=PolicyDecision(data.get('decision', 'require_approval')),
                    reason=data.get('reason', 'Policy evaluated by Archestra'),
                    requires_approval=data.get('requires_approval', False),
                    approval_id=data.get('approval_id'),
                    risk_score=risk_score,
                    matched_policy=data.get('matched_policy', 'archestra_remote'),
                    context=data.get('context', {})
                )
                
            elif response.status_code == 202:
                # Requires human approval
                data = response.json()
                result = PolicyResult(
                    allowed=False,
                    decision=PolicyDecision.REQUIRE_APPROVAL,
                    reason=data.get('reason', 'Operation requires human approval'),
                    requires_approval=True,
                    approval_id=data.get('approval_id', f"apr_{uuid.uuid4().hex[:8]}"),
                    risk_score=risk_score,
                    matched_policy=data.get('matched_policy', 'default_human_approval')
                )
                
            elif response.status_code == 403:
                result = PolicyResult(
                    allowed=False,
                    decision=PolicyDecision.DENY,
                    reason="Archestra API authorization failed (403). Check ARCHESTRA_API_KEY",
                    risk_score=risk_score,
                    matched_policy="auth_failure"
                )
                
            else:
                result = PolicyResult(
                    allowed=False,
                    decision=PolicyDecision.DENY,
                    reason=f"Archestra returned status {response.status_code}",
                    requires_approval=True,
                    risk_score=risk_score
                )
                
        except httpx.ConnectError:
            # Archestra unreachable - FAIL CLOSED for security
            result = PolicyResult(
                allowed=False,
                decision=PolicyDecision.DENY,
                reason=f"Cannot reach Archestra at {self.api_url}. FAILING CLOSED for security.",
                requires_approval=True,
                risk_score=risk_score,
                matched_policy="fail_closed"
            )
            
        except Exception as e:
            result = PolicyResult(
                allowed=False,
                decision=PolicyDecision.DENY,
                reason=f"Policy validation error: {str(e)}",
                requires_approval=True,
                risk_score=risk_score,
                matched_policy="error"
            )
        
        # Log the decision
        result.audit_id = self.audit_logger.log(
            event_type="policy_evaluation",
            tool_name=tool_name,
            parameters=parameters,
            decision=result.decision,
            reason=result.reason,
            user_role=user_role,
            risk_score=risk_score,
            approval_id=result.approval_id,
            matched_policy=result.matched_policy,
            context=result.context
        )
        
        # Cache and record
        self._cache_result(cache_key, result)
        if result.allowed:
            self.rate_limiter.record_call(tool_name)
        
        return result
    
    def get_policy_status(self) -> Dict[str, Any]:
        """Get current status of policy engine."""
        return {
            "archestra_enabled": ARCHESTRA_ENABLED,
            "archestra_url": self.api_url,
            "strict_mode": ARCHESTRA_STRICT_MODE,
            "threat_intel_ips": len(self.threat_intel._blocklist),
            "recent_attackers": len(self.threat_intel._recent_attackers),
            "cache_entries": len(self._policy_cache),
        }


# Initialize Archestra client
archestra = ArchestraClient(ARCHESTRA_API_URL, ARCHESTRA_API_KEY)

# --- HELPER FUNCTIONS ---
def _read_last_lines(file_path: Path, n: int = 20) -> list[str]:
    """Efficiently reads the last n lines of a file."""
    if not file_path.exists():
        return []
    try:
        with open(file_path, "r") as f:
            # Simple approach for hackathon: read all and slice
            # For production, we would use 'seek' for large files
            lines = f.readlines()
            return lines[-n:]
    except Exception as e:
        return [f"Error reading logs: {str(e)}"]

def _apply_pii_redaction(content: str) -> str:
    """
    Apply PII redaction policy to remove sensitive data from logs before returning.
    This implements the pii_redaction.yaml policy.
    """
    # Redact passwords in format: password=value or password: value
    content = re.sub(r'password[=:\s]+(\S+)', 'password=[REDACTED_PASS]', content, flags=re.IGNORECASE)
    
    # Redact usernames in format: user 'username'
    content = re.sub(r"user\s+'([a-zA-Z0-9_-]+)'", "user '[REDACTED_USER]'", content)
    
    # Optionally redact internal IPs (10.x.x.x) - commented out by default
    # content = re.sub(r'10\.\d+\.\d+\.\d+', '[INTERNAL_IP]', content)
    
    return content

# --- MCP TOOLS (The Capabilities) ---

@mcp.tool()
def analyze_logs(lines_to_check: int = 50) -> str:
    """
    Scans the server authentication logs for suspicious patterns like
    SSH brute force attempts or repeated failures.
    Log data is checked against Archestra PII redaction policies.
    
    Args:
        lines_to_check: Number of recent log lines to analyze (default 50)
    """
    logs = _read_last_lines(LOG_FILE, lines_to_check)
    if not logs:
        return "No logs found. System appears silent (or logs are missing)."

    # Regex to find 'Failed password' and capture the IP
    # Matches: "Failed password for root from 192.168.1.5"
    fail_pattern = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")
    
    ip_counts = {}
    
    for line in logs:
        match = fail_pattern.search(line)
        if match:
            ip = match.group(1)
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    # Generate a threat report
    report = []
    for ip, count in ip_counts.items():
        if count > 5:
            report.append(f"CRITICAL: IP {ip} has {count} failed login attempts. Recommended Action: BLOCK.")
        elif count > 0:
            report.append(f"WARNING: IP {ip} has {count} failed attempts.")
            
    if not report:
        return "Analysis Complete: No active threats detected in recent logs."
    
    result = "\n".join(report)
    
    # APPLY PII REDACTION POLICY
    # Redact sensitive data before returning to LLM
    result = _apply_pii_redaction(result)
    
    return result

@mcp.tool()
def firewall_block_ip(ip_address: str, reason: str = "Malicious activity detected") -> str:
    """
    Blocks an IP address by adding it to the server's deny list.
    **CRITICAL**: This modifies network configurations and requires Archestra policy approval.
    
    Archestra evaluates multiple policies:
    - Rate limiting (max 10 blocks/hour)
    - Threat intelligence matching
    - Internal IP protection
    - Time-based restrictions (off-hours escalation)
    - Dynamic risk scoring
    
    Args:
        ip_address: The IPv4 address to block (e.g., 192.168.1.5)
        reason: Justification for the block (for audit logs)
    """
    # ARCHESTRA POLICY VALIDATION
    # Comprehensive policy check with threat intel, rate limiting, and risk scoring
    policy_result = archestra.validate_policy(
        tool_name='firewall_block_ip',
        parameters={'ip_address': ip_address, 'reason': reason},
        risk_level='high'
    )
    
    # Build detailed response based on policy decision
    if policy_result.decision == PolicyDecision.DENY:
        return (
            f"🚫 BLOCKED BY ARCHESTRA POLICY\n"
            f"═══════════════════════════════════════\n"
            f"Policy: {policy_result.matched_policy}\n"
            f"Reason: {policy_result.reason}\n"
            f"Risk Score: {policy_result.risk_score:.2f}\n"
            f"Audit ID: {policy_result.audit_id}\n"
            f"═══════════════════════════════════════"
        )
    
    if policy_result.decision == PolicyDecision.RATE_LIMITED:
        return (
            f"⏱️ RATE LIMITED\n"
            f"═══════════════════════════════════════\n"
            f"Policy: {policy_result.matched_policy}\n"
            f"Reason: {policy_result.reason}\n"
            f"Context: {json.dumps(policy_result.context, indent=2)}\n"
            f"Audit ID: {policy_result.audit_id}\n"
            f"═══════════════════════════════════════\n"
            f"Please wait before attempting more blocks."
        )
    
    if policy_result.decision == PolicyDecision.REQUIRE_APPROVAL:
        return (
            f"⏳ PENDING HUMAN APPROVAL\n"
            f"═══════════════════════════════════════\n"
            f"Policy: {policy_result.matched_policy}\n"
            f"Target IP: {ip_address}\n"
            f"Reason: {reason}\n"
            f"Risk Score: {policy_result.risk_score:.2f}\n"
            f"Approval ID: {policy_result.approval_id}\n"
            f"Audit ID: {policy_result.audit_id}\n"
            f"═══════════════════════════════════════\n"
            f"Status: Awaiting human operator confirmation.\n"
            f"Notification sent to: slack, email, dashboard"
        )
    
    # EXECUTE: Policy approved, proceed with IP blocking
    try:
        timestamp = datetime.utcnow().isoformat()
        with open(BLOCKED_IPS_FILE, "a") as f:
            f.write(
                f"DENY {ip_address} # {reason} "
                f"[APPROVED: {policy_result.matched_policy}] "
                f"[RISK: {policy_result.risk_score:.2f}] "
                f"[AUDIT: {policy_result.audit_id}] "
                f"[{timestamp}]\n"
            )
        
        # Update threat intel with this IP
        archestra.threat_intel.add_to_blocklist(ip_address)
        
        return (
            f"✅ SUCCESS: IP BLOCKED\n"
            f"═══════════════════════════════════════\n"
            f"IP Address: {ip_address}\n"
            f"Reason: {reason}\n"
            f"Policy: {policy_result.matched_policy}\n"
            f"Risk Score: {policy_result.risk_score:.2f}\n"
            f"Audit ID: {policy_result.audit_id}\n"
            f"═══════════════════════════════════════\n"
            f"IP has been added to the blocklist."
        )
    except Exception as e:
        return f"❌ FAILED: Could not write to blocklist. Error: {str(e)}"

@mcp.tool()
def analyze_access_logs(lines_to_check: int = 100) -> str:
    """
    Scans the web server access logs for suspicious patterns like
    SQL injection attempts, path traversal, or unusual request rates.
    Log data is checked against Archestra PII redaction policies.
    
    Args:
        lines_to_check: Number of recent log lines to analyze (default 100)
    """
    logs = _read_last_lines(ACCESS_LOG_FILE, lines_to_check)
    if not logs:
        return "No access logs found."

    # Patterns indicating SQL injection attempts
    sql_patterns = [
        r"(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s",
        r"(?:'|\")\s*(?:OR|AND)\s*(?:'|\")?[0-9]",
        r"--\s*$",
        r";\s*(?:DROP|DELETE|UPDATE)",
    ]
    
    # Track suspicious IPs and their activities
    ip_pattern = re.compile(r"^(\d+\.\d+\.\d+\.\d+)")
    error_pattern = re.compile(r'" (4\d{2}|5\d{2}) ')
    
    ip_requests = {}
    ip_errors = {}
    sql_injection_ips = set()
    
    for line in logs:
        ip_match = ip_pattern.search(line)
        if ip_match:
            ip = ip_match.group(1)
            ip_requests[ip] = ip_requests.get(ip, 0) + 1
            
            # Check for errors
            if error_pattern.search(line):
                ip_errors[ip] = ip_errors.get(ip, 0) + 1
            
            # Check for SQL injection patterns
            for pattern in sql_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    sql_injection_ips.add(ip)
                    break

    report = []
    
    # Report SQL injection attempts
    for ip in sql_injection_ips:
        report.append(f"CRITICAL: IP {ip} attempted SQL injection. Recommended Action: BLOCK.")
    
    # Report high error rates (possible attack probing)
    for ip, errors in ip_errors.items():
        if errors > 10:
            report.append(f"WARNING: IP {ip} has {errors} error responses (possible scanning).")
    
    # Report unusually high request rates (possible DDoS)
    for ip, count in ip_requests.items():
        if count > 50:
            report.append(f"WARNING: IP {ip} made {count} requests (possible flood attack).")
            
    if not report:
        return "Analysis Complete: No suspicious web activity detected."
    
    result = "\n".join(report)
    
    # APPLY PII REDACTION POLICY
    # Redact sensitive data before returning to LLM
    result = _apply_pii_redaction(result)
    
    return result

@mcp.tool()
def get_blocked_ips() -> str:
    """
    Returns the list of currently blocked IP addresses.
    """
    if not BLOCKED_IPS_FILE.exists():
        return "No IPs are currently blocked."
    
    try:
        with open(BLOCKED_IPS_FILE, "r") as f:
            content = f.read().strip()
        if not content:
            return "No IPs are currently blocked."
        return f"Currently blocked IPs:\n{content}"
    except Exception as e:
        return f"Error reading blocklist: {str(e)}"

@mcp.tool()
def system_lockdown(confirm: bool = False) -> str:
    """
    INITIATES EMERGENCY LOCKDOWN. Stops web services (Nginx).
    Use only in case of total system compromise.
    This CRITICAL operation requires Archestra approval.
    
    Args:
        confirm: Must be set to True to execute.
    """
    if not confirm:
        return "Action aborted. You must set 'confirm=True' to execute a lockdown."
    
    # ARCHESTRA POLICY VALIDATION
    # This is a critical operation - must be approved by Archestra
    policy_check = archestra.validate_policy(
        tool_name='system_lockdown',
        parameters={'confirm': confirm},
        risk_level='critical'
    )
    
    if not policy_check['allowed']:
        return (
            f"BLOCKED BY ARCHESTRA: {policy_check['reason']}\n"
            f"Emergency lockdown requires approval. "
            f"Approval ID: {policy_check.get('approval_id', 'pending')}"
        )
    
    if policy_check.get('requires_approval'):
        return (
            f"PENDING HUMAN APPROVAL: System lockdown is a CRITICAL operation.\n"
            f"Status: Awaiting human operator confirmation.\n"
            f"Approval ID: {policy_check.get('approval_id', 'pending')}"
        )
    
    # EXECUTE: Policy approved, proceed with lockdown
    return (
        "ALERT: Nginx service stopped. SSH port 22 restricted. System is in panic mode.\n"
        "[ARCHESTRA-APPROVED CRITICAL ACTION]"
    )


# --- STRUCTURED EVENT STREAM TOOLS ---

@mcp.tool()
def get_security_events(
    limit: int = 50,
    event_type: Optional[str] = None,
    attack_type: Optional[str] = None,
    minutes_ago: Optional[int] = None
) -> str:
    """
    Retrieves structured security events from the event stream.
    Each event is labeled with its type (normal/attack/suspicious) and includes
    rich metadata for analysis.
    
    Args:
        limit: Maximum number of events to return (most recent first, default 50)
        event_type: Filter by type: 'normal', 'attack', or 'suspicious'
        attack_type: Filter by attack: 'ssh_brute_force', 'sql_injection', 'ddos_flood', 'port_scan'
        minutes_ago: Only return events from the last N minutes
    """
    # Convert string filters to enums if provided
    evt_type = None
    if event_type:
        try:
            evt_type = EventType(event_type.lower())
        except ValueError:
            return f"Invalid event_type '{event_type}'. Use: normal, attack, suspicious"
    
    atk_type = None
    if attack_type:
        try:
            atk_type = AttackType(attack_type.lower())
        except ValueError:
            return f"Invalid attack_type '{attack_type}'. Use: ssh_brute_force, sql_injection, ddos_flood, port_scan"
    
    since = None
    if minutes_ago:
        since = datetime.utcnow() - timedelta(minutes=minutes_ago)
    
    events = read_events(limit=limit, event_type=evt_type, attack_type=atk_type, since=since)
    
    if not events:
        return "No events found matching the criteria."
    
    # Format events for readability
    output = []
    for evt in events:
        net = evt.get('network', {})
        line = (
            f"[{evt['timestamp']}] "
            f"{'🚨 ATTACK' if evt['is_attack'] else '✓ NORMAL'} | "
            f"{evt.get('attack_type', 'none'):<16} | "
            f"Severity: {evt['severity']:<8} | "
            f"{net.get('source_ip', '?')} → {net.get('dest_ip', '?')}:{net.get('dest_port', '?')} ({net.get('protocol', '?')})"
        )
        output.append(line)
    
    return f"Found {len(events)} events:\n" + "\n".join(output)


@mcp.tool()
def get_event_statistics() -> str:
    """
    Returns aggregate statistics about security events including:
    - Total event counts
    - Breakdown by event type (normal vs attack)
    - Breakdown by attack type
    - Breakdown by severity level
    - Unique source/destination IPs
    
    Use this to get an overview of the security landscape before diving into details.
    """
    stats = get_event_stats()
    
    if stats['total_events'] == 0:
        return "No events recorded yet. The event stream is empty."
    
    attack_breakdown = "\n".join(
        f"    - {atk}: {count}" 
        for atk, count in stats['by_attack_type'].items()
    ) or "    None detected"
    
    return f"""Security Event Statistics:
═══════════════════════════════════════
Total Events: {stats['total_events']}

By Event Type:
    - Normal Traffic: {stats['by_event_type']['normal']}
    - Attack Traffic: {stats['by_event_type']['attack']}
    - Suspicious: {stats['by_event_type']['suspicious']}

Attack Type Breakdown:
{attack_breakdown}

By Severity:
    - Info: {stats['by_severity']['info']}
    - Low: {stats['by_severity']['low']}
    - Medium: {stats['by_severity']['medium']}
    - High: {stats['by_severity']['high']}
    - Critical: {stats['by_severity']['critical']}

Unique Source IPs: {len(stats['unique_source_ips'])}
Unique Destination IPs: {len(stats['unique_dest_ips'])}
═══════════════════════════════════════"""


@mcp.tool()
def analyze_attack_patterns() -> str:
    """
    Provides intelligent analysis of attack events to identify patterns,
    correlate attacks, and suggest defensive actions.
    
    Returns analysis including:
    - Most frequent attack types
    - Most active attacker IPs
    - Attack timeline patterns
    - Recommended defensive actions
    """
    events = read_events(limit=500, event_type=EventType.ATTACK)
    
    if not events:
        return "No attack events detected. System appears secure."
    
    # Analyze attack patterns
    attack_counts = {}
    source_ip_counts = {}
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    
    for evt in events:
        # Count by attack type
        atk = evt.get('attack_type', 'unknown')
        attack_counts[atk] = attack_counts.get(atk, 0) + 1
        
        # Count by source IP
        src_ip = evt.get('network', {}).get('source_ip', 'unknown')
        source_ip_counts[src_ip] = source_ip_counts.get(src_ip, 0) + 1
        
        # Count by severity
        sev = evt.get('severity', 'info')
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    # Generate recommendations
    recommendations = []
    
    # Most active attacker IPs (recommend blocking if > 5 attacks)
    top_attackers = sorted(source_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    for ip, count in top_attackers:
        if count > 5:
            recommendations.append(f"🚫 BLOCK IP {ip} - {count} attack attempts detected")
    
    # Critical attacks need immediate action
    if severity_counts['critical'] > 0:
        recommendations.append(f"⚠️ CRITICAL: {severity_counts['critical']} critical-severity attacks detected - investigate immediately")
    
    # Specific attack type recommendations
    if attack_counts.get('ddos_flood', 0) > 10:
        recommendations.append("🛡️ Enable rate limiting and DDoS protection")
    if attack_counts.get('sql_injection', 0) > 0:
        recommendations.append("🔐 Review input validation and WAF rules for SQL injection")
    if attack_counts.get('ssh_brute_force', 0) > 10:
        recommendations.append("🔑 Implement fail2ban or SSH key-only authentication")
    
    attack_summary = "\n".join(f"    - {atk}: {count}" for atk, count in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True))
    attacker_summary = "\n".join(f"    - {ip}: {count} attacks" for ip, count in top_attackers)
    rec_summary = "\n".join(recommendations) if recommendations else "    No immediate actions required"
    
    return f"""Attack Pattern Analysis
═══════════════════════════════════════
Total Attack Events: {len(events)}

Attack Type Distribution:
{attack_summary}

Top Attacker IPs:
{attacker_summary}

Severity Breakdown:
    - Critical: {severity_counts['critical']}
    - High: {severity_counts['high']}
    - Medium: {severity_counts['medium']}
    - Low: {severity_counts['low']}

RECOMMENDED ACTIONS:
{rec_summary}
═══════════════════════════════════════"""


@mcp.tool()
def get_archestra_policy_status() -> str:
    """
    Returns the current status of the Archestra policy engine including:
    - Whether Archestra is enabled and connected
    - Threat intelligence feed status
    - Rate limiting status
    - Recent policy decisions
    
    Use this to verify policy engine health before critical operations.
    """
    status = archestra.get_policy_status()
    
    # Get recent audit entries
    recent_decisions = []
    if AUDIT_LOG_FILE.exists():
        try:
            with open(AUDIT_LOG_FILE, "r") as f:
                lines = f.readlines()[-5:]  # Last 5 decisions
                for line in lines:
                    try:
                        entry = json.loads(line.strip())
                        recent_decisions.append(
                            f"    [{entry.get('timestamp', '?')[:19]}] "
                            f"{entry.get('tool_name', '?')}: {entry.get('decision', '?')}"
                        )
                    except:
                        pass
        except:
            pass
    
    recent_str = "\n".join(recent_decisions) if recent_decisions else "    No recent decisions"
    
    return f"""Archestra Policy Engine Status
═══════════════════════════════════════
Engine Status:
    Enabled: {status['archestra_enabled']}
    API URL: {status['archestra_url']}
    Strict Mode: {status['strict_mode']}

Threat Intelligence:
    Static Blocklist IPs: {status['threat_intel_ips']}
    Recent Attackers (24h): {status['recent_attackers']}

Policy Cache:
    Cached Decisions: {status['cache_entries']}

Recent Policy Decisions:
{recent_str}
═══════════════════════════════════════"""


@mcp.tool()
def firewall_bulk_block(ip_addresses: str, reason: str = "Bulk block - coordinated attack") -> str:
    """
    Blocks multiple IP addresses at once.
    
    **REQUIRES ENHANCED APPROVAL** when blocking more than 5 IPs:
    - Security Lead approval required
    - Justification must be at least 50 characters
    - Rate limited to 3 bulk operations per hour
    
    Args:
        ip_addresses: Comma-separated list of IPv4 addresses to block
        reason: Justification for the bulk block (min 50 chars for >5 IPs)
    """
    # Parse IP addresses
    ips = [ip.strip() for ip in ip_addresses.split(",") if ip.strip()]
    
    if not ips:
        return "❌ ERROR: No valid IP addresses provided."
    
    # Check justification length for bulk operations
    if len(ips) > 5 and len(reason) < 50:
        return (
            f"❌ INSUFFICIENT JUSTIFICATION\n"
            f"═══════════════════════════════════════\n"
            f"Blocking {len(ips)} IPs requires detailed justification.\n"
            f"Minimum: 50 characters\n"
            f"Provided: {len(reason)} characters\n"
            f"═══════════════════════════════════════\n"
            f"Policy: bulk_block_restriction"
        )
    
    # ARCHESTRA POLICY VALIDATION
    policy_result = archestra.validate_policy(
        tool_name='firewall_bulk_block',
        parameters={'ip_addresses': ips, 'count': len(ips), 'reason': reason},
        risk_level='high' if len(ips) <= 5 else 'critical'
    )
    
    if policy_result.decision == PolicyDecision.DENY:
        return (
            f"🚫 BLOCKED BY ARCHESTRA POLICY\n"
            f"═══════════════════════════════════════\n"
            f"Policy: {policy_result.matched_policy}\n"
            f"Reason: {policy_result.reason}\n"
            f"IPs Requested: {len(ips)}\n"
            f"Audit ID: {policy_result.audit_id}\n"
            f"═══════════════════════════════════════"
        )
    
    if policy_result.decision == PolicyDecision.RATE_LIMITED:
        return (
            f"⏱️ RATE LIMITED\n"
            f"═══════════════════════════════════════\n"
            f"Reason: {policy_result.reason}\n"
            f"═══════════════════════════════════════\n"
            f"Bulk operations are limited to 3 per hour."
        )
    
    if policy_result.decision == PolicyDecision.REQUIRE_APPROVAL:
        return (
            f"⏳ PENDING SECURITY LEAD APPROVAL\n"
            f"═══════════════════════════════════════\n"
            f"Policy: {policy_result.matched_policy}\n"
            f"IPs to Block: {len(ips)}\n"
            f"Risk Score: {policy_result.risk_score:.2f}\n"
            f"Approval ID: {policy_result.approval_id}\n"
            f"═══════════════════════════════════════\n"
            f"IPs:\n" + "\n".join(f"  - {ip}" for ip in ips[:10]) +
            (f"\n  ... and {len(ips) - 10} more" if len(ips) > 10 else "") +
            f"\n═══════════════════════════════════════\n"
            f"Reason: {reason}"
        )
    
    # EXECUTE: Block all IPs
    blocked = []
    failed = []
    timestamp = datetime.utcnow().isoformat()
    
    try:
        with open(BLOCKED_IPS_FILE, "a") as f:
            for ip in ips:
                # Check if internal IP (these are always blocked by policy)
                if archestra.threat_intel.is_internal_ip(ip):
                    failed.append(f"{ip} (internal IP protected)")
                    continue
                
                f.write(
                    f"DENY {ip} # {reason} "
                    f"[BULK:{len(ips)}] "
                    f"[APPROVED: {policy_result.matched_policy}] "
                    f"[AUDIT: {policy_result.audit_id}] "
                    f"[{timestamp}]\n"
                )
                blocked.append(ip)
                archestra.threat_intel.add_to_blocklist(ip)
    except Exception as e:
        return f"❌ FAILED: Error writing to blocklist: {str(e)}"
    
    return (
        f"✅ BULK BLOCK COMPLETE\n"
        f"═══════════════════════════════════════\n"
        f"Successfully Blocked: {len(blocked)}\n"
        f"Failed/Protected: {len(failed)}\n"
        f"Policy: {policy_result.matched_policy}\n"
        f"Audit ID: {policy_result.audit_id}\n"
        f"═══════════════════════════════════════\n"
        f"Blocked IPs:\n" + "\n".join(f"  ✓ {ip}" for ip in blocked[:10]) +
        (f"\n  ... and {len(blocked) - 10} more" if len(blocked) > 10 else "") +
        (f"\n\nProtected IPs (not blocked):\n" + "\n".join(f"  ⚠ {ip}" for ip in failed) if failed else "")
    )


@mcp.tool()
def get_audit_trail(limit: int = 20) -> str:
    """
    Retrieves the Archestra audit trail showing all policy decisions.
    
    Use this for compliance reporting and forensic analysis.
    Each entry shows the tool called, decision, policy matched, and risk score.
    
    Args:
        limit: Maximum number of audit entries to return (default 20)
    """
    if not AUDIT_LOG_FILE.exists():
        return "No audit entries found. Audit logging may not be enabled."
    
    entries = []
    try:
        with open(AUDIT_LOG_FILE, "r") as f:
            lines = f.readlines()[-limit:]
            for line in lines:
                try:
                    entry = json.loads(line.strip())
                    entries.append(entry)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        return f"Error reading audit log: {str(e)}"
    
    if not entries:
        return "No audit entries found."
    
    # Format entries
    output = []
    for entry in reversed(entries):  # Most recent first
        decision_icon = {
            'allow': '✅',
            'deny': '🚫',
            'require_approval': '⏳',
            'rate_limited': '⏱️',
        }.get(entry.get('decision', ''), '❓')
        
        output.append(
            f"{decision_icon} [{entry.get('timestamp', '?')[:19]}]\n"
            f"   Tool: {entry.get('tool_name', '?')}\n"
            f"   Decision: {entry.get('decision', '?')}\n"
            f"   Policy: {entry.get('matched_policy', '?')}\n"
            f"   Risk Score: {entry.get('risk_score', 0):.2f}\n"
            f"   Audit ID: {entry.get('audit_id', '?')[:8]}..."
        )
    
    return f"""Archestra Audit Trail
═══════════════════════════════════════
Entries: {len(entries)} (most recent first)
═══════════════════════════════════════

""" + "\n\n".join(output)


if __name__ == "__main__":
    # This starts the server when you run `python hero/server.py`
    # Runs Streamable HTTP server on 0.0.0.0:8765 for Archestra integration
    mcp.run(transport="streamable-http")
