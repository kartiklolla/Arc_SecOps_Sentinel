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
    
    GRAPH_WIDTH = 40  # Width of the actual graph bars
    
    DEFAULT_CSS = """
    PacketGraph {
        height: 14;
        padding: 0 1;
    }
    """
    
    # Use reactive to trigger re-renders
    _refresh_count = reactive(0)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.traffic_data = deque([0] * self.GRAPH_WIDTH, maxlen=self.GRAPH_WIDTH)
        self.peak_value = 0
        self.total_packets = 0
    
    def render(self) -> Text:
        """Render the graph with consistent box drawing."""
        max_val = max(self.traffic_data) if max(self.traffic_data) > 0 else 1
        inner_width = self.GRAPH_WIDTH + 2  # graph + padding
        total_width = inner_width + 2  # + borders
        
        # Build graph lines
        graph_lines = []
        for row in range(6, 0, -1):
            line = ""
            for val in self.traffic_data:
                height = int((val / max_val) * 6) if max_val > 0 else 0
                if height >= row:
                    line += "█"
                else:
                    line += " "
            graph_lines.append(line)
        
        current = self.traffic_data[-1] if self.traffic_data else 0
        
        text = Text()
        # Header - consistent width
        header = "─ THROUGHPUT "
        text.append("┌" + header + "─" * (inner_width - len(header)) + "┐\n", style="bold red")
        
        # Graph bars
        for line in graph_lines:
            text.append("│ ", style="red")
            text.append(line, style="bright_red")
            text.append(" │\n", style="red")
        
        # Separator
        text.append("├" + "─" * inner_width + "┤\n", style="red")
        
        # Stats line - fit within box
        stats = f" NOW:{current:>4} │ PEAK:{self.peak_value:>4} │ TOT:{self.total_packets:>6} "
        padding = inner_width - len(stats)
        text.append("│", style="red")
        text.append(stats[:inner_width], style="bright_red")
        if padding > 0:
            text.append(" " * padding, style="red")
        text.append("│\n", style="red")
        
        # Footer
        text.append("└" + "─" * inner_width + "┘", style="red")
        
        return text
    
    def add_data(self, packets: int) -> None:
        self.traffic_data.append(packets)
        self.total_packets += packets
        if packets > self.peak_value:
            self.peak_value = packets
        self._refresh_count += 1
    
    def reset(self) -> None:
        self.traffic_data = deque([0] * self.GRAPH_WIDTH, maxlen=self.GRAPH_WIDTH)
        self.peak_value = 0
        self.total_packets = 0
        self._refresh_count += 1


class PacketStream(Static):
    """Real-time scrolling packet stream display."""
    
    BOX_WIDTH = 58  # Inner width of the box
    
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
        header = "═══ PACKET STREAM "
        text.append("╔" + header + "═" * (self.BOX_WIDTH - len(header)) + "╗\n", style="bold red")
        
        if not self.packets:
            msg = "Awaiting packets..."
            text.append("║ ", style="red")
            text.append(msg, style="dim white")
            text.append(" " * (self.BOX_WIDTH - len(msg) - 1) + "║\n", style="red")
        else:
            for pkt in self.packets:
                line = f"{pkt['time']} {pkt['proto']:<4} {pkt['src']:<12}→{pkt['dst']:<12} {pkt['info']}"
                line = line[:self.BOX_WIDTH - 1]
                text.append("║ ", style="red")
                text.append(f"{pkt['time']} ", style="dim white")
                text.append(f"{pkt['proto']:<4} ", style="cyan")
                text.append(f"{pkt['src']:<12}", style="green")
                text.append("→", style="dim red")
                text.append(f"{pkt['dst']:<12} ", style="yellow")
                text.append(f"{pkt['info']:<6}", style="bright_red")
                # Calculate actual length and pad
                actual_len = 9 + 5 + 12 + 1 + 13 + 6  # time + proto + src + arrow + dst + info
                remaining = self.BOX_WIDTH - actual_len
                if remaining > 0:
                    text.append(" " * remaining, style="red")
                text.append("║\n", style="red")
        
        text.append("╚" + "═" * self.BOX_WIDTH + "╝", style="bold red")
        return text
    
    def add_packet(self, proto: str, src: str, dst: str, info: str) -> None:
        self.packets.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "proto": proto[:4],
            "src": src[:12],
            "dst": dst[:12],
            "info": info[:6]
        })
        self._refresh_count += 1


class HexViewer(Static):
    """Hex dump viewer for payload inspection."""
    
    BOX_WIDTH = 68  # Wide enough for hex + ascii
    
    DEFAULT_CSS = """
    HexViewer {
        height: 8;
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
            header = "═══ PAYLOAD "
            text.append("╔" + header + "═" * (self.BOX_WIDTH - len(header)) + "╗\n", style="bold red")
            msg = "No active payload"
            text.append("║ " + msg + " " * (self.BOX_WIDTH - len(msg) - 1) + "║\n", style="red")
            text.append("╚" + "═" * self.BOX_WIDTH + "╝", style="bold red")
            return text
        
        proto = self.current_meta.get('proto', 'N/A')
        src = self.current_meta.get('src', 'N/A')
        dst = self.current_meta.get('dst', 'N/A')
        
        # Header with metadata
        header = f"═══ PAYLOAD │ {proto} {src}→{dst} "
        text.append("╔" + header[:self.BOX_WIDTH] + "═" * max(0, self.BOX_WIDTH - len(header)) + "╗\n", style="bold red")
        
        raw_bytes = self.current_payload.encode('utf-8', errors='replace')
        offset = 0
        lines = 0
        
        while offset < len(raw_bytes) and lines < 3:
            chunk = raw_bytes[offset:offset + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(48)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk).ljust(16)
            
            # Format: "║ 0000  xx xx xx... │ ascii...│"
            line_content = f"{offset:04x}  {hex_part} │{ascii_part}│"
            text.append("║ ", style="red")
            text.append(f"{offset:04x}  ", style="dim red")
            text.append(hex_part, style="bright_red")
            text.append(" │", style="dim red")
            text.append(ascii_part, style="cyan")
            text.append("║\n", style="red")
            
            offset += 16
            lines += 1
        
        text.append("╚" + "═" * self.BOX_WIDTH + "╝", style="bold red")
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
    
    BAR_WIDTH = 30
    BOX_WIDTH = BAR_WIDTH + 10  # bar + padding + percent
    
    DEFAULT_CSS = """
    ProgressIndicator {
        height: 5;
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
            text.append("▸ ", style="dim green")
            text.append("READY", style="green")
            text.append(" │ ", style="dim red")
            text.append("Select an attack", style="dim white")
            return text
        
        filled = int(self.progress / 100 * self.BAR_WIDTH)
        bar = "█" * filled + "░" * (self.BAR_WIDTH - filled)
        
        text.append(f"► {self.attack_name[:20]} ", style="bold bright_red")
        text.append("ACTIVE\n", style="blink red")
        text.append("╔" + "═" * self.BOX_WIDTH + "╗\n", style="red")
        text.append("║ ", style="red")
        text.append(bar, style="bright_red")
        text.append(f" {self.progress:3}% ", style="bold yellow")
        text.append("║\n", style="red")
        text.append("╚" + "═" * self.BOX_WIDTH + "╝", style="red")
        
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
    
    BOX_WIDTH = 20
    
    DEFAULT_CSS = """
    SystemInfo {
        height: auto;
        padding: 1;
    }
    """
    
    def render(self) -> Text:
        text = Text()
        text.append("╔═══ NETWORK " + "═" * (self.BOX_WIDTH - 12) + "╗\n", style="bold red")
        
        src_line = f"SRC: {ATTACKER_IP}"
        text.append("║ ", style="red")
        text.append("SRC: ", style="cyan")
        text.append(ATTACKER_IP[:self.BOX_WIDTH - 7], style="white")
        text.append(" " * max(0, self.BOX_WIDTH - len(src_line) - 1) + "║\n", style="red")
        
        dst_line = f"DST: {TARGET_IP}"
        text.append("║ ", style="red")
        text.append("DST: ", style="yellow")
        text.append(TARGET_IP[:self.BOX_WIDTH - 7], style="bright_red")
        text.append(" " * max(0, self.BOX_WIDTH - len(dst_line) - 1) + "║\n", style="red")
        
        text.append("╚" + "═" * self.BOX_WIDTH + "╝", style="bold red")
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
