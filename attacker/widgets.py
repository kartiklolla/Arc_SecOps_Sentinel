"""
Custom widgets for the CyberStrike Console.
"""

from textual.widgets import Static
from textual.reactive import reactive
from collections import deque
from datetime import datetime
from rich.text import Text

from config import TARGET_IP, ATTACKER_IP


class PacketGraph(Static):
    """Real-time packet traffic graph visualization."""
    
    DEFAULT_CSS = """
    PacketGraph {
        height: 12;
        padding: 0 1;
    }
    """
    
    # Use reactive to trigger re-renders
    _refresh_count = reactive(0)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.traffic_data = deque([0] * 50, maxlen=50)
        self.peak_value = 0
        self.total_packets = 0
    
    def render(self) -> Text:
        """Render the graph."""
        max_val = max(self.traffic_data) if max(self.traffic_data) > 0 else 1
        
        graph_lines = []
        for row in range(8, 0, -1):
            line = ""
            for val in self.traffic_data:
                height = int((val / max_val) * 8) if max_val > 0 else 0
                if height >= row:
                    line += "█"
                else:
                    line += " "
            graph_lines.append(line)
        
        current = self.traffic_data[-1] if self.traffic_data else 0
        
        text = Text()
        text.append("┌─ THROUGHPUT ─", style="bold red")
        text.append("─" * 36, style="red")
        text.append("┐\n", style="bold red")
        
        for line in graph_lines:
            text.append("│ ", style="red")
            text.append(line, style="bold red")
            text.append(" │\n", style="red")
        
        text.append("├", style="red")
        text.append("─" * 52, style="dim red")
        text.append("┤\n", style="red")
        text.append("│ ", style="red")
        text.append(f"NOW: {current:>5} pkt/s", style="bright_red")
        text.append("  │  ", style="dim red")
        text.append(f"PEAK: {self.peak_value:>5} pkt/s", style="yellow")
        text.append("  │  ", style="dim red")
        text.append(f"TOTAL: {self.total_packets:>7}", style="cyan")
        text.append(" │\n", style="red")
        text.append("└", style="red")
        text.append("─" * 52, style="red")
        text.append("┘", style="red")
        
        return text
    
    def add_data(self, packets: int) -> None:
        self.traffic_data.append(packets)
        self.total_packets += packets
        if packets > self.peak_value:
            self.peak_value = packets
        self._refresh_count += 1
    
    def reset(self) -> None:
        self.traffic_data = deque([0] * 50, maxlen=50)
        self.peak_value = 0
        self.total_packets = 0
        self._refresh_count += 1


class PacketStream(Static):
    """Real-time scrolling packet stream display."""
    
    DEFAULT_CSS = """
    PacketStream {
        height: 12;
        padding: 0 1;
    }
    """
    
    _refresh_count = reactive(0)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.packets = deque(maxlen=8)
    
    def render(self) -> Text:
        text = Text()
        text.append("╔═══ PACKET STREAM ═══╗\n", style="bold red")
        
        if not self.packets:
            text.append("║ ", style="red")
            text.append("Awaiting packets...", style="dim white")
            text.append("\n", style="red")
        else:
            for pkt in self.packets:
                text.append("║ ", style="red")
                text.append(f"{pkt['time']} ", style="dim white")
                text.append(f"{pkt['proto']:<5} ", style="cyan")
                text.append(f"{pkt['src']:<15} → ", style="green")
                text.append(f"{pkt['dst']:<15} ", style="yellow")
                text.append(f"{pkt['info']}\n", style="bright_red")
        
        text.append("╚" + "═" * 22 + "╝", style="bold red")
        return text
    
    def add_packet(self, proto: str, src: str, dst: str, info: str) -> None:
        self.packets.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "proto": proto[:5],
            "src": src[:15],
            "dst": dst[:15],
            "info": info[:8]
        })
        self._refresh_count += 1


class HexViewer(Static):
    """Hex dump viewer for payload inspection."""
    
    DEFAULT_CSS = """
    HexViewer {
        height: 10;
        padding: 0 1;
    }
    """
    
    _refresh_count = reactive(0)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.current_payload = None
        self.current_meta = {}
    
    def render(self) -> Text:
        text = Text()
        
        if not self.current_payload:
            text.append("╔═══ PAYLOAD ═══╗\n", style="bold red")
            text.append("║ ", style="red")
            text.append("No active payload", style="dim white")
            text.append("\n╚═══════════════╝", style="bold red")
            return text
        
        proto = self.current_meta.get('proto', 'N/A')
        src = self.current_meta.get('src', 'N/A')
        dst = self.current_meta.get('dst', 'N/A')
        
        text.append("╔═══ PAYLOAD ═══╗ ", style="bold red")
        text.append(f"{proto} {src} → {dst}\n", style="dim white")
        text.append("╠" + "═" * 50 + "\n", style="red")
        
        raw_bytes = self.current_payload.encode('utf-8', errors='replace')
        offset = 0
        lines = 0
        
        while offset < len(raw_bytes) and lines < 3:
            chunk = raw_bytes[offset:offset + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(48)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            
            text.append(f"║ {offset:04x}  ", style="dim red")
            text.append(hex_part, style="bright_red")
            text.append(" │", style="dim red")
            text.append(ascii_part, style="cyan")
            text.append("│\n", style="dim red")
            
            offset += 16
            lines += 1
        
        text.append("╚" + "═" * 50, style="bold red")
        return text
    
    def show_payload(self, payload: str, proto: str, src: str, dst: str) -> None:
        self.current_payload = payload
        self.current_meta = {"proto": proto, "src": src, "dst": dst}
        self._refresh_count += 1
    
    def clear(self) -> None:
        self.current_payload = None
        self.current_meta = {}
        self._refresh_count += 1


class ProgressIndicator(Static):
    """Attack progress indicator."""
    
    DEFAULT_CSS = """
    ProgressIndicator {
        height: 4;
        padding: 0 1;
    }
    """
    
    _refresh_count = reactive(0)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attack_name = ""
        self.progress = 0
        self.is_active = False
    
    def render(self) -> Text:
        text = Text()
        
        if not self.is_active:
            text.append("▸ READY", style="dim green")
            return text
        
        filled = int(self.progress / 100 * 35)
        bar = "█" * filled + "░" * (35 - filled)
        
        text.append(f"► {self.attack_name} ", style="bold bright_red")
        text.append("RUNNING\n", style="red")
        text.append("╔" + "═" * 37 + "╗\n", style="red")
        text.append("║ ", style="red")
        text.append(bar, style="bright_red")
        text.append(" ║ ", style="red")
        text.append(f"{self.progress:3}%\n", style="bold yellow")
        text.append("╚" + "═" * 37 + "╝", style="red")
        
        return text
    
    def start(self, name: str) -> None:
        self.attack_name = name
        self.progress = 0
        self.is_active = True
        self._refresh_count += 1
    
    def set_progress(self, percent: int) -> None:
        self.progress = min(percent, 100)
        self._refresh_count += 1
    
    def complete(self) -> None:
        self.is_active = False
        self._refresh_count += 1


class SystemInfo(Static):
    """System information panel."""
    
    DEFAULT_CSS = """
    SystemInfo {
        height: auto;
        padding: 1;
    }
    """
    
    def render(self) -> Text:
        text = Text()
        text.append("╔═══ NETWORK ═══╗\n", style="bold red")
        text.append("║ ", style="red")
        text.append("SRC: ", style="cyan")
        text.append(f"{ATTACKER_IP}\n", style="white")
        text.append("║ ", style="red")
        text.append("DST: ", style="yellow")
        text.append(f"{TARGET_IP}\n", style="bright_red")
        text.append("╚═══════════════╝", style="bold red")
        return text


class StatusBar(Static):
    """Top status bar."""
    
    DEFAULT_CSS = """
    StatusBar {
        height: 1;
        background: #1a0000;
        padding: 0 1;
    }
    """
    
    _time = reactive("")
    
    def on_mount(self) -> None:
        self.set_interval(1.0, self._update_time)
        self._update_time()
    
    def _update_time(self) -> None:
        self._time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def render(self) -> Text:
        text = Text()
        text.append("● ", style="bold green")
        text.append("READY", style="green")
        text.append(" │ ", style="dim red")
        text.append("SRC: ", style="dim white")
        text.append(ATTACKER_IP, style="cyan")
        text.append(" │ ", style="dim red")
        text.append("DST: ", style="dim white")
        text.append(TARGET_IP, style="bright_red")
        text.append(" │ ", style="dim red")
        text.append(self._time, style="yellow")
        return text
