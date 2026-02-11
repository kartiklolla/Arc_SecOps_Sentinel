from textual.app import App, ComposeResult
from textual.containers import Container, Vertical, Horizontal
from textual.widgets import Button, Header, Footer, Log, Static, Label
from textual.binding import Binding
from rich.text import Text
import time
import random

# --- CONFIGURATION ---
# The logs your Agent is watching. 
# Ensure these match the paths in your Agent's code!
AUTH_LOG_PATH = "../shared_logs/auth.log"
ACCESS_LOG_PATH = "../shared_logs/access.log"

# --- CONFIGURATION ---
# The logs your Agent is watching. 
AUTH_LOG_PATH = "../shared_logs/auth.log"
ACCESS_LOG_PATH = "../shared_logs/access.log"

class PacketVisualizer(Static):
    """A widget to visualize network packets and payloads in real-time."""
    
    def on_mount(self) -> None:
        self.update("")

    def show_packet(self, src: str, dst: str, protocol: str, payload_hex: str) -> None:
        """Render a packet with a hex dump view."""
        timestamp = time.strftime("%H:%M:%S.%f")[:-3]
        
        # Create a hex dump representation
        hex_view = ""
        chars = ""
        for i in range(0, len(payload_hex), 2):
            byte = payload_hex[i:i+2]
            hex_view += f"[bold red]{byte}[/] "
            try:
                char = bytes.fromhex(byte).decode('utf-8')
                if not char.isprintable():
                    char = "."
            except:
                char = "."
            chars += f"[red]{char}[/]"
            
            if (i // 2 + 1) % 8 == 0:
                hex_view += "  "
                
        panel = f"""
[bold white]CAPTURED PACKET[/]  [dim]{timestamp}[/]
[bold cyan]SRC:[/] {src}  [bold cyan]DST:[/] {dst}  [bold yellow]PROTO:[/] {protocol}
[rule]
[bold red]{hex_view:<40}[/]  [white]│[/]  [red]{chars}[/]
"""
        self.update(panel)

class VillainConsole(App):
    """The Attacker Command & Control Dashboard."""
    
    CSS = """
    Screen {
        background: #0d0d0d;
        color: #ff0000;
    }
    
    #header {
        background: #200;
        color: #ff0000;
        text-align: center;
        text-style: bold;
        height: 3;
        content-align: center middle;
        border-bottom: double #ff0000;
    }

    Container {
        padding: 0;
    }

    #main_layout {
        height: 100%;
        width: 100%;
    }

    #controls {
        width: 25%;
        height: 100%;
        dock: left;
        border-right: heavy #ff0000;
        background: #100;
        padding: 1;
    }

    #right_panel {
        width: 75%;
        height: 100%;
        layout: vertical;
    }

    #terminal {
        height: 70%;
        width: 100%;
        background: #000;
        border-bottom: heavy #ff0000;
        padding: 1;
    }

    #visualizer {
        height: 30%;
        width: 100%;
        background: #080000;
        border: solid #400;
        padding: 1;
    }

    Button {
        width: 100%;
        margin-bottom: 1;
        background: #300;
        color: #ff0000;
        border: wide #ff0000;
        text-style: bold;
    }

    Button:hover {
        background: #ff0000;
        color: #fff;
    }
    
    .title {
        text-align: center;
        color: #ff0000;
        text-style: bold underline;
        margin-bottom: 1;
        padding-top: 1;
    }

    Log {
        background: #000;
        color: #ff0000;
        scrollbar-color: #ff0000;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit Console"),
        Binding("c", "clear_log", "Clear Terminal"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("█▀ █▄█ ▀█▀ █▀▀ █ █ █ █ █ █\nSYSTEM STATUS: ONLINE | ENCRYPTION: AES-256", id="header")
        
        with Container(id="main_layout"):
            # Left Panel: Attack Buttons
            with Vertical(id="controls"):
                yield Label(":: ATTACK VECTORS ::", classes="title")
                yield Button("SSH BRUTE FORCE", id="btn_ssh")
                yield Button("SQL INJECTION", id="btn_sql")
                yield Button("DDOS FLOOD", id="btn_ddos")
                yield Button("PORT SCAN (NMAP)", id="btn_nmap")
                yield Static("\n[dim]Connected to C2 Node\nLatency: 12ms\nVPN: ACTIVED[/]", markup=True)
            
            # Right Panel: Terminal + Visuals
            with Vertical(id="right_panel"):
                with Vertical(id="terminal"):
                    yield Label(">> SYSTEM LOGS", classes="title")
                    # markup=True fixes the issue where color tags are printed literally
                    yield Log(id="log_output", highlight=True)
                
                with Vertical(id="visualizer"):
                    yield Label(">> PACKET SNIFFER", classes="title")
                    yield PacketVisualizer(id="packet_viz")

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks and simulate attacks."""
        log = self.query_one("#log_output", Log)
        viz = self.query_one("#packet_viz", PacketVisualizer)
        
        if event.button.id == "btn_ssh":
            self.run_ssh_attack(log, viz)
        elif event.button.id == "btn_sql":
            self.run_sql_injection(log, viz)
        elif event.button.id == "btn_ddos":
            self.run_ddos(log, viz)
        elif event.button.id == "btn_nmap":
            self.run_port_scan(log, viz)

    # --- ATTACK SIMULATIONS ---

    def run_ssh_attack(self, log: Log, viz: PacketVisualizer):
        log.write_line(Text.from_markup("[bold red]>> INITIATING SSH BRUTE FORCE ATTACK...[/]"))
        target_ip = "192.168.1.105"
        passwords = ["123456", "password", "admin", "toor", "root", "qwerty"]
        
        try:
            with open(AUTH_LOG_PATH, "a") as f:
                for i in range(1, 15):
                    timestamp = time.strftime("%b %d %H:%M:%S")
                    pwd = random.choice(passwords)
                    
                    # Visualize Payload
                    payload = f"USER=root&PASS={pwd}"
                    hex_payload = payload.encode('utf-8').hex()
                    viz.show_packet("10.0.0.66", target_ip, "SSHv2", hex_payload)
                    
                    # Log Entry
                    entry = f"{timestamp} server sshd[{random.randint(1000,9999)}]: Failed password for root from {target_ip} port {random.randint(30000,60000)} ssh2\n"
                    f.write(entry)
                    
                    log.write_line(Text.from_markup(f"   [red]Trying root:{pwd:<10}... [bold red]FAILED[/][/]"))
                    time.sleep(0.15) 
            
            log.write_line(Text.from_markup(f"[bold green]>> ATTACK COMPLETE. Payloads sent to {target_ip}[/]"))
        except FileNotFoundError:
            log.write_line(Text.from_markup(f"[bold yellow]ERROR: Could not find {AUTH_LOG_PATH}.[/]"))

    def run_sql_injection(self, log: Log, viz: PacketVisualizer):
        log.write_line(Text.from_markup("[bold yellow]>> INJECTING SQL PAYLOADS INTO WEB PORTAL...[/]"))
        payloads = ["' OR '1'='1", "UNION SELECT * FROM users", "DROP TABLE users;--", "admin' --"]
        
        try:
            with open(ACCESS_LOG_PATH, "a") as f:
                for payload in payloads:
                    timestamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000")
                    
                    # Visualize Payload
                    http_payload = f"GET /login?u={payload} HTTP/1.1"
                    hex_p = http_payload.encode('utf-8').hex()
                    viz.show_packet("10.0.0.66", "192.168.1.105", "HTTP", hex_p)

                    entry = f'192.168.1.105 - - [{timestamp}] "GET /login.php?user={payload} HTTP/1.1" 403 0 "-" "Mozilla/5.0"\n'
                    f.write(entry)
                    log.write_line(Text.from_markup(f"   [yellow]Payload sent: {payload}[/]"))
                    time.sleep(0.5)
            log.write_line(Text.from_markup("[bold green]>> INJECTION BATCH COMPLETE.[/]"))
        except FileNotFoundError:
            log.write_line(Text.from_markup(f"[bold yellow]ERROR: Could not find {ACCESS_LOG_PATH}.[/]"))

    def run_ddos(self, log: Log, viz: PacketVisualizer):
        log.write_line(Text.from_markup("[bold cyan]>> LAUNCHING LOIC DDOS FLOOD...[/]"))
        viz.update("[bold red blink]!!! FLOODING TARGET !!![/]\n[white]Packets/sec: 10,000[/]")
        
        try:
            with open(ACCESS_LOG_PATH, "a") as f:
                # Batch write for speed
                chunk = ""
                for _ in range(50):
                    chunk += f'192.168.1.105 - - [01/Jan/2026:00:00:00] "GET / HTTP/1.1" 200 1024\n'
                
                for _ in range(10): # 10 chunks
                    f.write(chunk)
                    log.write_line(Text.from_markup(f"   [cyan]Sending 500 packets...[/]"))
                    time.sleep(0.05)
                    
            log.write_line(Text.from_markup("[bold green]>> TARGET SATURATED.[/]"))
            viz.update("[bold green]TARGET DOWN[/]")
        except Exception as e:
            log.write(str(e))

    def run_port_scan(self, log: Log, viz: PacketVisualizer):
        log.write_line(Text.from_markup("[bold magenta]>> MAPPING NETWORK TOPOLOGY...[/]"))
        viz.update("[bold magenta]SCANNING PORTS 1-1000...[/]")
        
        open_ports = [22, 80, 443, 3306]
        for port in [21, 22, 23, 80, 443, 3306, 8080]:
            status = "OPEN" if port in open_ports else "CLOSED"
            color = "green" if status == "OPEN" else "red"
            
            viz.show_packet("10.0.0.66", "192.168.1.105", "TCP/SYN", f"PORT={port}")
            log.write_line(Text.from_markup(f"   [{color}]Port {port:<5} : {status}[/]"))
            time.sleep(0.2)
        
        log.write_line(Text.from_markup("[bold green]>> SCAN COMPLETE[/]"))

    def action_clear_log(self):
        self.query_one("#log_output", Log).clear()

if __name__ == "__main__":
    app = VillainConsole()
    app.run()
