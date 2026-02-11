from mcp.server.fastmcp import FastMCP
import os
import re
from pathlib import Path

# --- CONFIGURATION ---
# Define the name of your agent for Archestra
mcp = FastMCP("SecOps Sentinel")

# PATHS: These must match the folder structure we defined.
# We go up one level (..) to reach the shared_logs folder.
BASE_DIR = Path(__file__).parent.parent
LOG_FILE = BASE_DIR / "shared_logs" / "auth.log"
ACCESS_LOG_FILE = BASE_DIR / "shared_logs" / "access.log"
BLOCKED_IPS_FILE = BASE_DIR / "shared_logs" / "blocked_ips.txt"

# Ensure the shared_logs directory exists
BLOCKED_IPS_FILE.parent.mkdir(parents=True, exist_ok=True)

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

# --- MCP TOOLS (The Capabilities) ---

@mcp.tool()
def analyze_logs(lines_to_check: int = 50) -> str:
    """
    Scans the server authentication logs for suspicious patterns like
    SSH brute force attempts or repeated failures.
    
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
        
    return "\n".join(report)

@mcp.tool()
def firewall_block_ip(ip_address: str, reason: str = "Malicious activity detected") -> str:
    """
    Blocks an IP address by adding it to the server's deny list.
    **CRITICAL**: This modifies network configurations.
    
    Args:
        ip_address: The IPv4 address to block (e.g., 192.168.1.5)
        reason: Justification for the block (for audit logs)
    """
    # Validation (Simple check to prevent blocking localhost)
    if ip_address in ["127.0.0.1", "localhost", "0.0.0.0"]:
        return "ERROR: Safety Guardrail Triggered. Cannot block localhost."

    # In a real app, this would run: subprocess.run(["iptables", "-A", "INPUT", ...])
    # For the hackathon, we write to a file to be safe and visible.
    try:
        with open(BLOCKED_IPS_FILE, "a") as f:
            f.write(f"DENY {ip_address} # {reason}\n")
        return f"SUCCESS: IP {ip_address} has been added to the Blocklist."
    except Exception as e:
        return f"FAILED: Could not write to blocklist. Error: {str(e)}"

@mcp.tool()
def analyze_access_logs(lines_to_check: int = 100) -> str:
    """
    Scans the web server access logs for suspicious patterns like
    SQL injection attempts, path traversal, or unusual request rates.
    
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
        
    return "\n".join(report)

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
    
    Args:
        confirm: Must be set to True to execute.
    """
    if not confirm:
        return "Action aborted. You must set 'confirm=True' to execute a lockdown."
    
    # Simulating the service stop
    return "ALERT: Nginx service stopped. SSH port 22 restricted. System is in panic mode."

if __name__ == "__main__":
    # This starts the server when you run `python hero/server.py`
    mcp.run()
