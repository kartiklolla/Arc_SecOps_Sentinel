"""
Configuration settings for the CyberStrike Console.
"""

# --- LOG PATHS ---
AUTH_LOG_PATH = "../shared_logs/auth.log"
ACCESS_LOG_PATH = "../shared_logs/access.log"

# --- COLOR SCHEME (Red/Black Hacker Theme) ---
COLORS = {
    "primary": "#ff0040",       # Cyber red
    "secondary": "#cc0033",     # Darker red
    "accent": "#ff1a1a",        # Bright red
    "highlight": "#ff3366",     # Pink-red highlight
    "warning": "#ffcc00",       # Amber
    "success": "#00ff00",       # Green for success
    "info": "#00ffff",          # Cyan
    "background": "#0a0a0a",    # Near black
    "surface": "#121212",       # Dark surface
    "border": "#330000",        # Dark red border
    "text": "#ff0040",          # Primary text
    "text_dim": "#661a1a",      # Dimmed text
}

# --- TARGET CONFIGURATION ---
TARGET_IP = "192.168.1.105"
ATTACKER_IP = "10.0.0.66"

# --- ATTACK DATA ---
SSH_PASSWORDS = [
    "123456", "password", "admin", "toor", "root", 
    "qwerty", "letmein", "welcome", "monkey", "dragon"
]

SSH_USERNAMES = ["root", "admin", "user", "ubuntu", "test"]

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "admin' --",
    "' UNION SELECT null,null,null --",
    "' UNION SELECT username,password FROM users --",
    "'; DROP TABLE users; --",
    "1' AND (SELECT COUNT(*) FROM users) > 0 --",
    "' OR SLEEP(5) --",
    "-1' UNION SELECT @@version --",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables)) --"
]

PORT_SCAN_DATA = {
    21: ("FTP", "vsftpd 3.0.3", False),
    22: ("SSH", "OpenSSH 8.2p1", True),
    23: ("Telnet", "N/A", False),
    25: ("SMTP", "Postfix", False),
    53: ("DNS", "BIND 9.16", False),
    80: ("HTTP", "nginx/1.18.0", True),
    110: ("POP3", "Dovecot", False),
    143: ("IMAP", "Dovecot", False),
    443: ("HTTPS", "nginx/1.18.0", True),
    993: ("IMAPS", "Dovecot", False),
    3306: ("MySQL", "MySQL 8.0.28", True),
    5432: ("PostgreSQL", "N/A", False),
    6379: ("Redis", "N/A", False),
    8080: ("HTTP-Proxy", "Apache Tomcat", True),
    8443: ("HTTPS-Alt", "N/A", False),
}
