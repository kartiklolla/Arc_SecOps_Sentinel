"""
Structured Event Stream for Security Operations.

Provides a unified event format for both normal and attack traffic,
allowing AI agents to distinguish between traffic types using explicit labels.
"""

import json
import uuid
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, Literal
from enum import Enum


class EventType(str, Enum):
    """Classification of traffic events."""
    NORMAL = "normal"
    ATTACK = "attack"
    SUSPICIOUS = "suspicious"


class AttackType(str, Enum):
    """Types of attacks for labeling."""
    NONE = "none"
    SSH_BRUTE_FORCE = "ssh_brute_force"
    SQL_INJECTION = "sql_injection"
    DDOS_FLOOD = "ddos_flood"
    PORT_SCAN = "port_scan"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"


class Severity(str, Enum):
    """Severity levels for events."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Thread-safe file writing
_write_lock = threading.Lock()

# Default event log path - ensure directory exists
EVENT_LOG_PATH = Path(__file__).parent / "events.jsonl"
Path(__file__).parent.mkdir(parents=True, exist_ok=True)


def emit_event(
    event_type: EventType,
    source_ip: str,
    dest_ip: str,
    dest_port: int,
    protocol: str,
    payload: Optional[str] = None,
    attack_type: AttackType = AttackType.NONE,
    severity: Severity = Severity.INFO,
    metadata: Optional[Dict[str, Any]] = None,
    log_path: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Emit a structured event to the event log.
    
    Args:
        event_type: Classification (normal, attack, suspicious)
        source_ip: Source IP address
        dest_ip: Destination IP address
        dest_port: Destination port
        protocol: Protocol (TCP, UDP, HTTP, SSH, etc.)
        payload: Optional payload data
        attack_type: Type of attack if event_type is ATTACK
        severity: Severity level
        metadata: Additional context data
        log_path: Custom log path (defaults to shared_logs/events.jsonl)
    
    Returns:
        The event dictionary that was written
    """
    event = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": event_type.value,
        "is_attack": event_type == EventType.ATTACK,
        "attack_type": attack_type.value if event_type == EventType.ATTACK else None,
        "severity": severity.value,
        "network": {
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "protocol": protocol
        },
        "payload": payload,
        "metadata": metadata or {}
    }
    
    target_path = log_path or EVENT_LOG_PATH
    
    with _write_lock:
        with open(target_path, "a") as f:
            f.write(json.dumps(event) + "\n")
            f.flush()
    
    return event


def emit_normal_traffic(
    source_ip: str,
    dest_ip: str,
    dest_port: int,
    protocol: str,
    payload: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Convenience function for normal traffic events."""
    return emit_event(
        event_type=EventType.NORMAL,
        source_ip=source_ip,
        dest_ip=dest_ip,
        dest_port=dest_port,
        protocol=protocol,
        payload=payload,
        attack_type=AttackType.NONE,
        severity=Severity.INFO,
        metadata=metadata
    )


def emit_attack(
    attack_type: AttackType,
    source_ip: str,
    dest_ip: str,
    dest_port: int,
    protocol: str,
    severity: Severity = Severity.HIGH,
    payload: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Convenience function for attack events."""
    return emit_event(
        event_type=EventType.ATTACK,
        source_ip=source_ip,
        dest_ip=dest_ip,
        dest_port=dest_port,
        protocol=protocol,
        payload=payload,
        attack_type=attack_type,
        severity=severity,
        metadata=metadata
    )


def read_events(
    limit: int = 100,
    event_type: Optional[EventType] = None,
    attack_type: Optional[AttackType] = None,
    since: Optional[datetime] = None,
    log_path: Optional[Path] = None
) -> list[Dict[str, Any]]:
    """
    Read events from the event log with optional filtering.
    
    Args:
        limit: Maximum number of events to return (most recent first)
        event_type: Filter by event type
        attack_type: Filter by attack type
        since: Only return events after this timestamp
        log_path: Custom log path
    
    Returns:
        List of event dictionaries
    """
    target_path = log_path or EVENT_LOG_PATH
    
    if not target_path.exists():
        return []
    
    events = []
    with open(target_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                
                # Apply filters
                if event_type and event.get("event_type") != event_type.value:
                    continue
                if attack_type and event.get("attack_type") != attack_type.value:
                    continue
                if since:
                    event_time = datetime.fromisoformat(event["timestamp"].rstrip("Z"))
                    if event_time < since:
                        continue
                
                events.append(event)
            except json.JSONDecodeError:
                continue
    
    # Return most recent first, limited
    return list(reversed(events[-limit:]))


def get_event_stats(log_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Get statistics about events in the log.
    
    Returns:
        Dictionary with counts by type, attack type, severity, etc.
    """
    target_path = log_path or EVENT_LOG_PATH
    
    stats = {
        "total_events": 0,
        "by_event_type": {"normal": 0, "attack": 0, "suspicious": 0},
        "by_attack_type": {},
        "by_severity": {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
        "unique_source_ips": set(),
        "unique_dest_ips": set()
    }
    
    if not target_path.exists():
        stats["unique_source_ips"] = []
        stats["unique_dest_ips"] = []
        return stats
    
    with open(target_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                stats["total_events"] += 1
                
                event_type = event.get("event_type", "normal")
                if event_type in stats["by_event_type"]:
                    stats["by_event_type"][event_type] += 1
                
                attack_type = event.get("attack_type")
                if attack_type:
                    stats["by_attack_type"][attack_type] = stats["by_attack_type"].get(attack_type, 0) + 1
                
                severity = event.get("severity", "info")
                if severity in stats["by_severity"]:
                    stats["by_severity"][severity] += 1
                
                network = event.get("network", {})
                if network.get("source_ip"):
                    stats["unique_source_ips"].add(network["source_ip"])
                if network.get("dest_ip"):
                    stats["unique_dest_ips"].add(network["dest_ip"])
                    
            except json.JSONDecodeError:
                continue
    
    # Convert sets to lists for JSON serialization
    stats["unique_source_ips"] = list(stats["unique_source_ips"])
    stats["unique_dest_ips"] = list(stats["unique_dest_ips"])
    
    return stats


def clear_events(log_path: Optional[Path] = None) -> None:
    """Clear all events from the log."""
    target_path = log_path or EVENT_LOG_PATH
    with _write_lock:
        with open(target_path, "w") as f:
            pass
