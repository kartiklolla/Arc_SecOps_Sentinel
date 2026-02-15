from mcp.server.fastmcp import FastMCP
import os
import re
import httpx
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
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
# We go up one level (..) to reach the shared_logs folder.
BASE_DIR = Path(__file__).parent.parent
LOG_FILE = BASE_DIR / "shared_logs" / "auth.log"
ACCESS_LOG_FILE = BASE_DIR / "shared_logs" / "access.log"
BLOCKED_IPS_FILE = BASE_DIR / "shared_logs" / "blocked_ips.txt"

# ARCHESTRA CONFIGURATION
ARCHESTRA_ENABLED = os.getenv("ARCHESTRA_ENABLED", "true").lower() == "true"
ARCHESTRA_API_URL = os.getenv("ARCHESTRA_API_URL", "http://localhost:9000")
ARCHESTRA_API_KEY = os.getenv("ARCHESTRA_API_KEY", "").strip()

# Debug: Print loaded config (remove in production)
print(f"[DEBUG] ARCHESTRA_ENABLED: {ARCHESTRA_ENABLED}")
print(f"[DEBUG] ARCHESTRA_API_URL: {ARCHESTRA_API_URL}")
print(f"[DEBUG] ARCHESTRA_API_KEY loaded: {'Yes (' + str(len(ARCHESTRA_API_KEY)) + ' chars)' if ARCHESTRA_API_KEY else 'No (empty)'}")

# Ensure the shared_logs directory exists
BLOCKED_IPS_FILE.parent.mkdir(parents=True, exist_ok=True)

# --- ARCHESTRA POLICY ENGINE ---
class ArchestraClient:
    """
    Client for communicating with Archestra policy validation API.
    Archestra acts as a reverse proxy and firewall for tool calls,
    enforcing security policies before allowing dangerous operations.
    """
    
    def __init__(self, api_url: str, api_key: str = ""):
        self.api_url = api_url
        self.api_key = api_key
        self.client = httpx.Client(timeout=10.0)
    
    def validate_policy(
        self, 
        tool_name: str, 
        parameters: Dict[str, Any],
        risk_level: str = "medium"
    ) -> Dict[str, Any]:
        """
        Validate a tool call against Archestra policies.
        
        Args:
            tool_name: Name of the tool being called (e.g., 'firewall_block_ip')
            parameters: Tool parameters as a dictionary
            risk_level: Risk level of the operation ('low', 'medium', 'high', 'critical')
        
        Returns:
            {
                'allowed': bool,
                'reason': str,
                'requires_approval': bool,
                'approval_id': Optional[str]
            }
        """
        if not ARCHESTRA_ENABLED:
            return {
                'allowed': True,
                'reason': 'Archestra is disabled',
                'requires_approval': False,
                'approval_id': None
            }
        
        try:
            payload = {
                'tool': tool_name,
                'parameters': parameters,
                'risk_level': risk_level,
                'agent': 'SecOps Sentinel'
            }
            
            headers = {}
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
            
            response = self.client.post(
                f"{self.api_url}/api/v1/validate-policy",
                json=payload,
                headers=headers
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 202:
                # Request accepted but requires human approval
                return response.json()
            elif response.status_code == 403:
                # Authentication/Authorization error
                return {
                    'allowed': False,
                    'reason': f'Archestra API authorization failed (403 Forbidden). Check ARCHESTRA_API_KEY in .env',
                    'requires_approval': True,
                    'approval_id': None
                }
            else:
                # Policy check failed or error occurred
                return {
                    'allowed': False,
                    'reason': f'Archestra returned status {response.status_code}: {response.text[:100]}',
                    'requires_approval': True,
                    'approval_id': None
                }
        except httpx.ConnectError:
            # Archestra is unreachable - fail closed for security
            return {
                'allowed': False,
                'reason': f'Cannot reach Archestra at {self.api_url}. Failing closed for security.',
                'requires_approval': True,
                'approval_id': None
            }
        except Exception as e:
            return {
                'allowed': False,
                'reason': f'Policy validation error: {str(e)}',
                'requires_approval': True,
                'approval_id': None
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
    
    Args:
        ip_address: The IPv4 address to block (e.g., 192.168.1.5)
        reason: Justification for the block (for audit logs)
    """
    # Local safety check (prevent blocking localhost)
    if ip_address in ["127.0.0.1", "localhost", "0.0.0.0"]:
        return "ERROR: Safety Guardrail Triggered. Cannot block localhost."
    
    # ARCHESTRA POLICY VALIDATION
    # Check with Archestra before executing this high-risk operation
    policy_check = archestra.validate_policy(
        tool_name='firewall_block_ip',
        parameters={'ip_address': ip_address, 'reason': reason},
        risk_level='high'
    )
    
    if not policy_check['allowed']:
        return (
            f"BLOCKED BY ARCHESTRA: {policy_check['reason']}\n"
            f"This operation requires approval. "
            f"Approval ID: {policy_check.get('approval_id', 'pending')}"
        )
    
    if policy_check.get('requires_approval'):
        return (
            f"PENDING HUMAN APPROVAL: IP blocking requires explicit authorization per policy.\n"
            f"Target IP: {ip_address}\n"
            f"Reason: {reason}\n"
            f"Approval ID: {policy_check.get('approval_id', 'pending')}\n"
            f"Status: Awaiting human operator confirmation."
        )
    
    # EXECUTE: Policy approved, proceed with IP blocking
    try:
        with open(BLOCKED_IPS_FILE, "a") as f:
            f.write(f"DENY {ip_address} # {reason} [APPROVED by Archestra]\n")
        return f"SUCCESS: IP {ip_address} has been added to the Blocklist (Archestra-approved)."
    except Exception as e:
        return f"FAILED: Could not write to blocklist. Error: {str(e)}"

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


if __name__ == "__main__":
    # This starts the server when you run `python hero/server.py`
    # Runs Streamable HTTP server on 0.0.0.0:8765 for Archestra integration
    mcp.run(transport="streamable-http")
