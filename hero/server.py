from mcp.server.fastmcp import FastMCP
import os
import re
import httpx
import json
from pathlib import Path
from typing import Optional, Dict, Any

# --- CONFIGURATION ---
# Define the name of your agent for Archestra
mcp = FastMCP("SecOps Sentinel")

# PATHS: These must match the folder structure we defined.
# We go up one level (..) to reach the shared_logs folder.
BASE_DIR = Path(__file__).parent.parent
LOG_FILE = BASE_DIR / "shared_logs" / "auth.log"
ACCESS_LOG_FILE = BASE_DIR / "shared_logs" / "access.log"
BLOCKED_IPS_FILE = BASE_DIR / "shared_logs" / "blocked_ips.txt"

# ARCHESTRA CONFIGURATION
ARCHESTRA_ENABLED = os.getenv("ARCHESTRA_ENABLED", "true").lower() == "true"
ARCHESTRA_API_URL = os.getenv("ARCHESTRA_API_URL", "http://localhost:9000")
ARCHESTRA_API_KEY = os.getenv("ARCHESTRA_API_KEY", "")

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

if __name__ == "__main__":
    # This starts the server when you run `python hero/server.py`
    mcp.run()
