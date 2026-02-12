"""
Normal Traffic Generator for SecOps Sentinel.

Generates realistic normal traffic patterns to create a mixed traffic stream
that helps the AI agent learn to distinguish between normal and attack traffic.
"""

import sys
import time
import random
import argparse
from pathlib import Path
from datetime import datetime

# Add shared_logs to path
sys.path.insert(0, str(Path(__file__).parent.parent / "shared_logs"))

from events import emit_normal_traffic, EventType, Severity


# Realistic normal traffic patterns
NORMAL_ENDPOINTS = [
    ("/", "GET", 200),
    ("/index.html", "GET", 200),
    ("/about", "GET", 200),
    ("/contact", "GET", 200),
    ("/products", "GET", 200),
    ("/api/health", "GET", 200),
    ("/api/users", "GET", 200),
    ("/api/products", "GET", 200),
    ("/static/css/style.css", "GET", 200),
    ("/static/js/app.js", "GET", 200),
    ("/images/logo.png", "GET", 200),
    ("/login", "POST", 200),
    ("/search", "GET", 200),
]

NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15",
    "curl/7.68.0",
]

# Legitimate internal IPs (corporate network simulation)
LEGITIMATE_IPS = [
    "192.168.1.10", "192.168.1.15", "192.168.1.20", "192.168.1.25",
    "192.168.1.30", "192.168.1.35", "192.168.1.40", "192.168.1.45",
    "10.0.0.5", "10.0.0.10", "10.0.0.15", "10.0.0.20",
]

TARGET_IP = "192.168.1.105"


def generate_normal_http_traffic(count: int = 1):
    """Generate normal HTTP traffic events."""
    for _ in range(count):
        endpoint, method, status = random.choice(NORMAL_ENDPOINTS)
        source_ip = random.choice(LEGITIMATE_IPS)
        user_agent = random.choice(NORMAL_USER_AGENTS)
        
        payload = f"{method} {endpoint} HTTP/1.1\r\nHost: {TARGET_IP}\r\nUser-Agent: {user_agent}"
        
        emit_normal_traffic(
            source_ip=source_ip,
            dest_ip=TARGET_IP,
            dest_port=80,
            protocol="HTTP",
            payload=payload,
            metadata={
                "endpoint": endpoint,
                "method": method,
                "status_code": status,
                "user_agent": user_agent[:50]
            }
        )


def generate_normal_ssh_traffic(count: int = 1):
    """Generate normal SSH connection events."""
    for _ in range(count):
        source_ip = random.choice(LEGITIMATE_IPS)
        port = random.randint(40000, 60000)
        
        # Normal SSH events: successful auth, key exchange, session start
        events = [
            ("key_exchange", "SSH-2.0 Key Exchange Init"),
            ("auth_success", "Accepted publickey authentication"),
            ("session_open", "Session opened for user admin"),
        ]
        
        event_type, payload = random.choice(events)
        
        emit_normal_traffic(
            source_ip=source_ip,
            dest_ip=TARGET_IP,
            dest_port=22,
            protocol="SSH",
            payload=payload,
            metadata={
                "event_type": event_type,
                "source_port": port,
                "auth_method": "publickey"
            }
        )


def generate_normal_dns_traffic(count: int = 1):
    """Generate normal DNS query events."""
    domains = [
        "example.com", "api.internal.local", "auth.corporate.net",
        "cdn.example.com", "mail.example.com"
    ]
    
    for _ in range(count):
        source_ip = random.choice(LEGITIMATE_IPS)
        domain = random.choice(domains)
        
        emit_normal_traffic(
            source_ip=source_ip,
            dest_ip="8.8.8.8",
            dest_port=53,
            protocol="DNS",
            payload=f"Query: A {domain}",
            metadata={
                "query_type": "A",
                "domain": domain,
                "response": "NOERROR"
            }
        )


def generate_normal_database_traffic(count: int = 1):
    """Generate normal database connection events."""
    queries = [
        "SELECT id, name FROM users WHERE active = 1",
        "SELECT * FROM products LIMIT 10",
        "INSERT INTO audit_log (action, timestamp) VALUES ('login', NOW())",
        "UPDATE sessions SET last_activity = NOW() WHERE session_id = ?",
    ]
    
    for _ in range(count):
        source_ip = random.choice(LEGITIMATE_IPS[:4])  # Only app servers
        query = random.choice(queries)
        
        emit_normal_traffic(
            source_ip=source_ip,
            dest_ip=TARGET_IP,
            dest_port=5432,  # PostgreSQL
            protocol="PostgreSQL",
            payload=query,
            metadata={
                "query_type": query.split()[0],
                "execution_time_ms": random.randint(1, 50)
            }
        )


def run_traffic_generator(
    duration_seconds: int = 60,
    events_per_second: float = 2.0,
    verbose: bool = True
):
    """
    Run the normal traffic generator.
    
    Args:
        duration_seconds: How long to run (0 for infinite)
        events_per_second: Average events to generate per second
        verbose: Print status messages
    """
    generators = [
        (generate_normal_http_traffic, 0.5),      # 50% HTTP
        (generate_normal_ssh_traffic, 0.2),       # 20% SSH
        (generate_normal_dns_traffic, 0.15),      # 15% DNS
        (generate_normal_database_traffic, 0.15), # 15% DB
    ]
    
    if verbose:
        print(f"Starting normal traffic generator")
        print(f"   Rate: ~{events_per_second} events/sec")
        print(f"   Duration: {'infinite' if duration_seconds == 0 else f'{duration_seconds}s'}")
        print(f"   Press Ctrl+C to stop\n")
    
    start_time = time.time()
    event_count = 0
    
    try:
        while True:
            # Check duration
            if duration_seconds > 0 and (time.time() - start_time) >= duration_seconds:
                break
            
            # Select generator based on weights
            rand = random.random()
            cumulative = 0
            for gen_func, weight in generators:
                cumulative += weight
                if rand <= cumulative:
                    gen_func(1)
                    event_count += 1
                    break
            
            if verbose and event_count % 10 == 0:
                print(f"   Generated {event_count} normal events...", end="\r")
            
            # Sleep for random interval (Poisson-like distribution)
            sleep_time = random.expovariate(events_per_second)
            time.sleep(min(sleep_time, 2.0))  # Cap at 2 seconds
            
    except KeyboardInterrupt:
        pass
    
    if verbose:
        elapsed = time.time() - start_time
        print(f"\n✓ Generated {event_count} normal traffic events in {elapsed:.1f}s")
        print(f"   Actual rate: {event_count/elapsed:.1f} events/sec")


def main():
    parser = argparse.ArgumentParser(
        description="Generate normal traffic for SecOps Sentinel training"
    )
    parser.add_argument(
        "-d", "--duration",
        type=int,
        default=60,
        help="Duration in seconds (0 for infinite, default: 60)"
    )
    parser.add_argument(
        "-r", "--rate",
        type=float,
        default=2.0,
        help="Events per second (default: 2.0)"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress output"
    )
    parser.add_argument(
        "--burst",
        type=int,
        default=0,
        help="Generate N events instantly and exit"
    )
    
    args = parser.parse_args()
    
    if args.burst > 0:
        # Burst mode: generate N events quickly
        print(f"Generating {args.burst} normal traffic events...")
        for i in range(args.burst):
            generate_normal_http_traffic(1)
            if i % 5 == 0:
                generate_normal_ssh_traffic(1)
            if i % 7 == 0:
                generate_normal_dns_traffic(1)
        print(f"✓ Done!")
    else:
        run_traffic_generator(
            duration_seconds=args.duration,
            events_per_second=args.rate,
            verbose=not args.quiet
        )


if __name__ == "__main__":
    main()
