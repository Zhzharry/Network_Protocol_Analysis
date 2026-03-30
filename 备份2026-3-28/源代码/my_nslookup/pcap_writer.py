"""将原始帧写入 pcap。"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from scapy.all import Ether, wrpcap


def save_pcap(
    packets_bytes_list: list[bytes],
    filename: str = "capture.pcap",
    *,
    console: Console | None = None,
) -> None:
    scapy_pkts = []
    for p in packets_bytes_list:
        if not p:
            continue
        scapy_pkts.append(Ether(p))
    wrpcap(filename, scapy_pkts)
    c = console or Console(highlight=False)
    c.print(
        Panel(
            f"已写入 [bold cyan]{len(scapy_pkts)}[/bold] 个数据包\n"
            f"[dim]{filename}[/dim]",
            title="pcap",
            border_style="dim",
        )
    )
