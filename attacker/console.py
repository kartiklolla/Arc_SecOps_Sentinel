"""
CyberStrike Console - Elite Hacker Command & Control Dashboard
Main application entry point.
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Vertical, Horizontal
from textual.widgets import Button, Footer, RichLog, Static, Label
from textual.binding import Binding
from textual import work
from textual.worker import get_current_worker

from widgets import (
    PacketGraph,
    PacketStream,
    HexViewer,
    ProgressIndicator,
    SystemInfo,
    StatusBar
)
from attacks import AttackRunner


# ASCII Banner
BANNER = """
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║   ██║   ██║  ██║██║██║  ██╗███████╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
"""


class CyberStrikeConsole(App):
    """The Attacker Command & Control Dashboard."""
    
    CSS = """
    Screen {
        background: #0a0a0a;
        color: #ff0040;
    }
    
    /* Header Section */
    #header_section {
        height: 8;
        width: 100%;
        background: #0a0a0a;
        border-bottom: heavy #ff0040;
    }
    
    #banner {
        color: #ff0040;
        text-align: center;
        height: 6;
    }
    
    /* Main Layout */
    #main_container {
        height: 100%;
        width: 100%;
        layout: horizontal;
    }
    
    /* Left Panel - Controls */
    #left_panel {
        width: 20;
        height: 100%;
        border-right: heavy #ff0040;
        background: #0d0d0d;
        padding: 1;
    }
    
    #attack_label {
        text-align: center;
        color: #ff0040;
        text-style: bold;
        background: #1a0000;
        margin-bottom: 1;
        padding: 0 1;
    }
    
    Button {
        width: 100%;
        margin-bottom: 1;
        background: #1a0000;
        color: #ff0040;
        border: tall #ff0040;
        text-style: bold;
    }
    
    Button:hover {
        background: #ff0040;
        color: #000;
    }
    
    Button:focus {
        background: #330000;
        border: tall #ff3366;
    }
    
    Button.normal-btn {
        background: #001a00;
        color: #00ff00;
        border: tall #00ff00;
    }
    
    Button.normal-btn:hover {
        background: #00ff00;
        color: #000;
    }
    
    /* Center Panel - Log + Hex */
    #center_panel {
        width: 1fr;
        height: 100%;
        padding: 0 1;
    }
    
    #log_container {
        height: 50%;
        background: #050505;
        border: solid #330000;
        padding: 1;
    }
    
    #log_label {
        color: #ff0040;
        text-style: bold;
        text-align: center;
        background: #1a0000;
        margin-bottom: 1;
    }
    
    Log {
        background: #050505;
        color: #ff0040;
        scrollbar-color: #ff0040;
        scrollbar-background: #0a0a0a;
    }
    
    #hex_container {
        height: 25%;
        background: #050505;
        border: solid #330000;
        padding: 1;
    }
    
    #progress_container {
        height: 25%;
        background: #050505;
        border: solid #330000;
        padding: 1;
    }
    
    /* Right Panel - Packet Visualization */
    #right_panel {
        width: 55;
        height: 100%;
        border-left: heavy #ff0040;
        background: #0d0d0d;
        padding: 1;
    }
    
    #packet_stream_container {
        height: 40%;
        background: #050505;
        border: solid #330000;
        padding: 1;
    }
    
    #graph_container {
        height: 60%;
        background: #050505;
        border: solid #330000;
        padding: 1;
    }
    
    Footer {
        background: #1a0000;
        color: #ff0040;
    }
    
    /* Widget styling */
    SystemInfo {
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("c", "clear_log", "Clear"),
        Binding("1", "attack_ssh", "SSH"),
        Binding("2", "attack_sql", "SQLi"),
        Binding("3", "attack_ddos", "DDoS"),
        Binding("4", "attack_scan", "Scan"),
    ]

    def compose(self) -> ComposeResult:
        """Build the UI layout."""
        
        # Header with banner
        with Vertical(id="header_section"):
            yield Static(BANNER, id="banner")
            yield StatusBar()
        
        # Main content area
        with Container(id="main_container"):
            
            # Left Panel - Attack Controls
            with Vertical(id="left_panel"):
                yield Label("╔═ ATTACKS ═╗", id="attack_label")
                yield Button("SSH Brute [1]", id="btn_ssh")
                yield Button("SQL Inject [2]", id="btn_sql")
                yield Button("DDoS Flood [3]", id="btn_ddos")
                yield Button("Port Scan [4]", id="btn_scan")
                yield Button("Normal Traffic [5]", id="btn_normal", classes="normal-btn")
                yield SystemInfo()
            
            # Center Panel - Command Output
            with Vertical(id="center_panel"):
                with Vertical(id="log_container"):
                    yield Label("OUTPUT", id="log_label")
                    yield RichLog(id="log_output", highlight=True, max_lines=200, markup=True)
                
                with Vertical(id="hex_container"):
                    yield HexViewer(id="hex_viewer")
                
                with Vertical(id="progress_container"):
                    yield ProgressIndicator(id="progress")
            
            # Right Panel - Packet Visualization
            with Vertical(id="right_panel"):
                with Vertical(id="packet_stream_container"):
                    yield PacketStream(id="packet_stream")
                
                with Vertical(id="graph_container"):
                    yield PacketGraph(id="packet_graph")
        
        yield Footer()

    def on_mount(self) -> None:
        """Initialize on startup."""
        log = self.query_one("#log_output", RichLog)
        log.write("[dim white]Console initialized. Select an attack vector to begin.[/]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        button_id = event.button.id
        
        if button_id == "btn_ssh":
            self.action_attack_ssh()
        elif button_id == "btn_sql":
            self.action_attack_sql()
        elif button_id == "btn_ddos":
            self.action_attack_ddos()
        elif button_id == "btn_scan":
            self.action_attack_scan()
        elif button_id == "btn_normal":
            self.action_normal_traffic()

    def _get_attack_runner(self) -> AttackRunner:
        """Create an attack runner with current widget references."""
        return AttackRunner(
            log=self.query_one("#log_output", RichLog),
            hex_viewer=self.query_one("#hex_viewer", HexViewer),
            packet_stream=self.query_one("#packet_stream", PacketStream),
            packet_graph=self.query_one("#packet_graph", PacketGraph),
            progress=self.query_one("#progress", ProgressIndicator)
        )

    # --- ATTACK ACTIONS ---

    def action_attack_ssh(self) -> None:
        """Launch SSH brute force attack."""
        self._run_ssh_attack()

    def action_attack_sql(self) -> None:
        """Launch SQL injection attack."""
        self._run_sql_attack()

    def action_attack_ddos(self) -> None:
        """Launch DDoS flood attack."""
        self._run_ddos_attack()

    def action_attack_scan(self) -> None:
        """Launch port scan."""
        self._run_port_scan()

    def action_normal_traffic(self) -> None:
        """Generate normal traffic."""
        self._run_normal_traffic()

    @work(exclusive=True, thread=True)
    def _run_ssh_attack(self) -> None:
        """Worker for SSH attack."""
        runner = self._get_attack_runner()
        runner.run_ssh_bruteforce(self.call_from_thread)

    @work(exclusive=True, thread=True)
    def _run_sql_attack(self) -> None:
        """Worker for SQL injection attack."""
        runner = self._get_attack_runner()
        runner.run_sql_injection(self.call_from_thread)

    @work(exclusive=True, thread=True)
    def _run_ddos_attack(self) -> None:
        """Worker for DDoS attack."""
        runner = self._get_attack_runner()
        runner.run_ddos_flood(self.call_from_thread)

    @work(exclusive=True, thread=True)
    def _run_port_scan(self) -> None:
        """Worker for port scan."""
        runner = self._get_attack_runner()
        runner.run_port_scan(self.call_from_thread)

    @work(exclusive=True, thread=True)
    def _run_normal_traffic(self) -> None:
        """Worker for normal traffic generation."""
        from normal_traffic import run_traffic_generator
        log = self.query_one("#log_output", RichLog)
        progress = self.query_one("#progress", ProgressIndicator)
        packet_graph = self.query_one("#packet_graph", PacketGraph)
        
        self.call_from_thread(progress.start, "NORMAL TRAFFIC")
        self.call_from_thread(log.write, "[bold green]╔══════════════════════════════════════════════════════════╗[/]")
        self.call_from_thread(log.write, "[bold green]║  GENERATING NORMAL TRAFFIC PATTERNS                      ║[/]")
        self.call_from_thread(log.write, "[bold green]╚══════════════════════════════════════════════════════════╝[/]")
        
        # Generate traffic in bursts with progress updates
        import time
        for i in range(10):
            from normal_traffic import generate_normal_http_traffic, generate_normal_ssh_traffic
            generate_normal_http_traffic(5)
            generate_normal_ssh_traffic(2)
            self.call_from_thread(progress.set_progress, (i + 1) * 10)
            self.call_from_thread(packet_graph.add_data, 50 + (i * 10))
            self.call_from_thread(log.write, f"   [green]●[/] Generated batch {i+1}/10 - [cyan]7 events[/]")
            time.sleep(0.3)
        
        self.call_from_thread(progress.complete)
        self.call_from_thread(log.write, "[bold green]╔══════════════════════════════════════════════════════════╗[/]")
        self.call_from_thread(log.write, "[bold green]║  ✓ NORMAL TRAFFIC GENERATION COMPLETE - 70 events        ║[/]")
        self.call_from_thread(log.write, "[bold green]╚══════════════════════════════════════════════════════════╝[/]")

    def action_clear_log(self) -> None:
        """Clear the command output log."""
        self.query_one("#log_output", RichLog).clear()
        self.query_one("#packet_graph", PacketGraph).reset()


if __name__ == "__main__":
    app = CyberStrikeConsole()
    app.run()
