"""
Attack simulation logic for the CyberStrike Console.
"""

import sys
import time
import random
from pathlib import Path
from textual.widgets import RichLog

# Add shared_logs to path for events module
sys.path.insert(0, str(Path(__file__).parent.parent / "shared_logs"))

from events import emit_attack, AttackType, Severity
from config import (
    AUTH_LOG_PATH, ACCESS_LOG_PATH,
    TARGET_IP, ATTACKER_IP,
    SSH_PASSWORDS, SSH_USERNAMES,
    SQL_PAYLOADS, PORT_SCAN_DATA
)


class AttackRunner:
    """Handles attack execution with visualization callbacks."""
    
    def __init__(self, log: RichLog, hex_viewer, packet_stream, packet_graph, progress):
        self.log = log
        self.hex_viewer = hex_viewer
        self.packet_stream = packet_stream
        self.packet_graph = packet_graph
        self.progress = progress
        self._cancelled = False
    
    def cancel(self):
        """Cancel the current attack."""
        self._cancelled = True
    
    def _log_header(self, title: str, color: str = "red"):
        """Log a styled header."""
        self.log.write(f"[bold {color}]╔══════════════════════════════════════════════════════════╗[/]")
        self.log.write(f"[bold {color}]║  {title:<56}║[/]")
        self.log.write(f"[bold {color}]╚══════════════════════════════════════════════════════════╝[/]")
    
    def _log_footer(self, message: str, color: str = "green"):
        """Log a styled footer."""
        self.log.write(f"[bold {color}]╔══════════════════════════════════════════════════════════╗[/]")
        self.log.write(f"[bold {color}]║  {message:<56}║[/]")
        self.log.write(f"[bold {color}]╚══════════════════════════════════════════════════════════╝[/]")
    
    def run_ssh_bruteforce(self, call_from_thread):
        """Execute SSH brute force attack."""
        self._cancelled = False
        
        call_from_thread(self.progress.start, "SSH BRUTE FORCE")
        call_from_thread(self._log_header, f"INITIATING SSH BRUTE FORCE → {TARGET_IP}:22")
        
        total_attempts = 20
        
        try:
            with open(AUTH_LOG_PATH, "a") as f:
                for i in range(1, total_attempts + 1):
                    if self._cancelled:
                        break
                    
                    user = random.choice(SSH_USERNAMES)
                    pwd = random.choice(SSH_PASSWORDS)
                    port = random.randint(40000, 60000)
                    timestamp = time.strftime("%b %d %H:%M:%S")
                    
                    # Update progress
                    pct = int((i / total_attempts) * 100)
                    call_from_thread(self.progress.set_progress, pct)
                    
                    # Visualize payload
                    payload = f"SSH-2.0-OpenSSH_8.2\\r\\nuser={user}&pass={pwd}"
                    call_from_thread(self.hex_viewer.show_payload, payload, "SSHv2", ATTACKER_IP, TARGET_IP)
                    
                    # Add to packet stream
                    call_from_thread(self.packet_stream.add_packet, "SSH", f"{ATTACKER_IP}:{port}", f"{TARGET_IP}:22", "AUTH")
                    
                    # Update graph
                    packets = random.randint(50, 200)
                    call_from_thread(self.packet_graph.add_data, packets)
                    
                    # Write to log file
                    entry = f"{timestamp} server sshd[{random.randint(1000,9999)}]: Failed password for {user} from {ATTACKER_IP} port {port} ssh2\n"
                    f.write(entry)
                    f.flush()
                    
                    # Emit structured event for agent
                    emit_attack(
                        attack_type=AttackType.SSH_BRUTE_FORCE,
                        source_ip=ATTACKER_IP,
                        dest_ip=TARGET_IP,
                        dest_port=22,
                        protocol="SSH",
                        severity=Severity.HIGH,
                        payload=payload,
                        metadata={"username": user, "attempt": i, "source_port": port}
                    )
                    
                    # Console output
                    call_from_thread(
                        self.log.write,
                        f"   [cyan]#{i:03}[/] [dim]Trying[/] [yellow]{user}[/]:[red]{pwd:<12}[/] [bold red]✗ FAILED[/]"
                    )
                    
                    time.sleep(0.2)
            
            call_from_thread(self.progress.complete)
            call_from_thread(self._log_footer, f"✓ ATTACK COMPLETE - {total_attempts} payloads delivered", "green")
            
        except FileNotFoundError:
            call_from_thread(
                self.log.write,
                f"[bold red]⚠ ERROR: {AUTH_LOG_PATH} not found[/]"
            )
            call_from_thread(self.progress.complete)
    
    def run_sql_injection(self, call_from_thread):
        """Execute SQL injection attack."""
        self._cancelled = False
        
        call_from_thread(self.progress.start, "SQL INJECTION")
        call_from_thread(self._log_header, f"SQL INJECTION → http://{TARGET_IP}/login.php", "yellow")
        
        try:
            with open(ACCESS_LOG_PATH, "a") as f:
                for i, payload in enumerate(SQL_PAYLOADS, 1):
                    if self._cancelled:
                        break
                    
                    pct = int((i / len(SQL_PAYLOADS)) * 100)
                    call_from_thread(self.progress.set_progress, pct)
                    
                    timestamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000")
                    
                    # HTTP request visualization
                    http_req = f"POST /login.php HTTP/1.1\\r\\nHost: {TARGET_IP}\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\n\\r\\nusername={payload}&password=test"
                    call_from_thread(self.hex_viewer.show_payload, http_req, "HTTP/1.1", ATTACKER_IP, TARGET_IP)
                    
                    # Packet stream
                    call_from_thread(self.packet_stream.add_packet, "HTTP", ATTACKER_IP, f"{TARGET_IP}:80", "POST")
                    
                    # Graph update
                    call_from_thread(self.packet_graph.add_data, random.randint(100, 300))
                    
                    # Write to log
                    entry = f'{ATTACKER_IP} - - [{timestamp}] "POST /login.php HTTP/1.1" 500 0 "-" "SQLMap/1.6"\n'
                    f.write(entry)
                    f.flush()
                    
                    # Emit structured event for agent
                    emit_attack(
                        attack_type=AttackType.SQL_INJECTION,
                        source_ip=ATTACKER_IP,
                        dest_ip=TARGET_IP,
                        dest_port=80,
                        protocol="HTTP",
                        severity=Severity.CRITICAL,
                        payload=payload,
                        metadata={"endpoint": "/login.php", "method": "POST", "attempt": i}
                    )
                    
                    status = random.choice(["[red]500 ERROR[/]", "[yellow]403 FORBIDDEN[/]", "[cyan]200 OK[/]"])
                    display_payload = payload[:35] + "..." if len(payload) > 35 else payload
                    call_from_thread(
                        self.log.write,
                        f"   [cyan]#{i:02}[/] [dim]Injecting:[/] [yellow]{display_payload}[/] {status}"
                    )
                    
                    time.sleep(0.4)
            
            call_from_thread(self.progress.complete)
            call_from_thread(self._log_footer, "✓ SQL INJECTION BATCH COMPLETE", "green")
            
        except FileNotFoundError:
            call_from_thread(
                self.log.write,
                f"[bold red]⚠ ERROR: {ACCESS_LOG_PATH} not found[/]"
            )
            call_from_thread(self.progress.complete)
    
    def run_ddos_flood(self, call_from_thread):
        """Execute DDoS flood attack."""
        self._cancelled = False
        
        call_from_thread(self.progress.start, "DDOS FLOOD")
        call_from_thread(self._log_header, f"████ DDOS FLOOD → {TARGET_IP} ████", "red")
        
        try:
            with open(ACCESS_LOG_PATH, "a") as f:
                total_waves = 15
                
                for wave in range(1, total_waves + 1):
                    if self._cancelled:
                        break
                    
                    pct = int((wave / total_waves) * 100)
                    call_from_thread(self.progress.set_progress, pct)
                    
                    packets_per_wave = random.randint(500, 2000)
                    
                    # Random botnet source IP
                    src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                    
                    # Payload visualization
                    flood_payload = f"GET / HTTP/1.1\\r\\nHost: {TARGET_IP}\\r\\nX-Forwarded-For: {src_ip}\\r\\n" + "A" * 50
                    call_from_thread(self.hex_viewer.show_payload, flood_payload, "FLOOD", src_ip, TARGET_IP)
                    
                    # Multiple packet entries
                    for _ in range(3):
                        rand_src = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                        call_from_thread(self.packet_stream.add_packet, "FLOOD", rand_src, f"{TARGET_IP}:80", "GET")
                    
                    # Spike the graph
                    call_from_thread(self.packet_graph.add_data, packets_per_wave)
                    
                    botnet_nodes = random.randint(100, 500)
                    
                    # Write log entries
                    for _ in range(50):
                        rand_src = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                        f.write(f'{rand_src} - - [{time.strftime("%d/%b/%Y:%H:%M:%S")}] "GET / HTTP/1.1" 200 1024\n')
                        
                        # Emit structured event for each DDoS packet
                        emit_attack(
                            attack_type=AttackType.DDOS_FLOOD,
                            source_ip=rand_src,
                            dest_ip=TARGET_IP,
                            dest_port=80,
                            protocol="HTTP",
                            severity=Severity.CRITICAL,
                            payload=flood_payload[:100],
                            metadata={"wave": wave, "packets_in_wave": packets_per_wave, "botnet_nodes": botnet_nodes}
                        )
                    f.flush()
                    call_from_thread(
                        self.log.write,
                        f"   [red]WAVE {wave:02}/{total_waves}[/] │ [cyan]Packets:[/] [bright_red]{packets_per_wave:,}[/] │ [yellow]Botnet: {botnet_nodes}[/]"
                    )
                    
                    time.sleep(0.15)
            
            call_from_thread(self.progress.complete)
            call_from_thread(self._log_footer, "████ TARGET SATURATED - SERVICE DOWN ████", "red")
            
        except Exception as e:
            call_from_thread(
                self.log.write,
                f"[bold red]⚠ ERROR: {str(e)}[/]"
            )
            call_from_thread(self.progress.complete)
    
    def run_port_scan(self, call_from_thread):
        """Execute network port scan."""
        self._cancelled = False
        
        call_from_thread(self.progress.start, "PORT SCAN")
        call_from_thread(self._log_header, f"NMAP STEALTH SYN SCAN → {TARGET_IP}", "magenta")
        
        ports = list(PORT_SCAN_DATA.keys())
        
        for i, port in enumerate(ports, 1):
            if self._cancelled:
                break
            
            pct = int((i / len(ports)) * 100)
            call_from_thread(self.progress.set_progress, pct)
            
            service, version, is_open = PORT_SCAN_DATA[port]
            
            # SYN packet visualization
            syn_payload = f"TCP SYN Packet\\r\\nSRC PORT: {random.randint(40000, 60000)}\\r\\nDST PORT: {port}\\r\\nSEQ: {random.randint(1000000, 9999999)}\\r\\nFLAGS: SYN"
            call_from_thread(self.hex_viewer.show_payload, syn_payload, "TCP/SYN", ATTACKER_IP, TARGET_IP)
            
            # Packet stream
            flag = "SYN-ACK" if is_open else "RST"
            call_from_thread(self.packet_stream.add_packet, "TCP", ATTACKER_IP, f"{TARGET_IP}:{port}", flag)
            
            # Graph
            call_from_thread(self.packet_graph.add_data, random.randint(10, 50))
            
            # Emit structured event for agent
            emit_attack(
                attack_type=AttackType.PORT_SCAN,
                source_ip=ATTACKER_IP,
                dest_ip=TARGET_IP,
                dest_port=port,
                protocol="TCP",
                severity=Severity.MEDIUM,
                payload=syn_payload,
                metadata={"service": service, "version": version, "is_open": is_open, "scan_type": "SYN"}
            )
            
            # Log result
            if is_open:
                call_from_thread(
                    self.log.write,
                    f"   [bright_green]✓[/] [cyan]{port:>5}/tcp[/] [bright_green]OPEN[/]   [yellow]{service:<12}[/] [dim]{version}[/]"
                )
            else:
                call_from_thread(
                    self.log.write,
                    f"   [red]✗[/] [dim]{port:>5}/tcp[/] [red]CLOSED[/] [dim]{service}[/]"
                )
            
            time.sleep(0.25)
        
        call_from_thread(self.progress.complete)
        open_count = sum(1 for _, (_, _, o) in PORT_SCAN_DATA.items() if o)
        call_from_thread(self._log_footer, f"✓ SCAN COMPLETE - {open_count} OPEN PORTS FOUND", "magenta")
