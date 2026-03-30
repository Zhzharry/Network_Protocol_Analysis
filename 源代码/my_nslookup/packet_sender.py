"""L2 发包与 DNS 应答捕获（Scapy）。"""
from __future__ import annotations

import socket
import threading
import time
from typing import TYPE_CHECKING

from scapy.all import DNS, Ether, UDP, sendp, sniff

if TYPE_CHECKING:
    from rich.console import Console


def send_and_receive(
    raw_packet_bytes: bytes,
    iface: str,
    src_port: int,
    transaction_id: int,
    timeout: float = 5.0,
    *,
    console: "Console | None" = None,
    layers: set[str] | None = None,
) -> tuple[object | None, float | None]:
    """
    先占住 UDP 源端口，避免内核因“无监听端口”向 DNS 回 ICMP Port Unreachable；
    在线程中 sniff，主线程 sendp 发以太帧；按 Transaction ID 匹配应答。

    返回 (应答报文或 None, 往返时延毫秒或 None)。时延为从发出以太帧到收到匹配应答的 wall-clock。
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", src_port))
    except OSError:
        pass

    responses: list = []

    def lfilter(pkt) -> bool:
        try:
            if UDP not in pkt or DNS not in pkt:
                return False
            u = pkt[UDP]
            d = pkt[DNS]
            return (
                u.sport == 53
                and u.dport == src_port
                and int(d.id) == transaction_id
            )
        except Exception:
            return False

    def capture() -> None:
        pkts = sniff(
            iface=iface,
            filter=f"udp and src port 53 and dst port {src_port}",
            timeout=timeout,
            lfilter=lfilter,
            count=1,
        )
        if pkts:
            responses.extend(pkts)

    t = threading.Thread(target=capture, daemon=True)
    t.start()
    time.sleep(0.15)

    pkt = Ether(raw_packet_bytes)
    t0 = time.perf_counter()
    sendp(pkt, iface=iface, verbose=False)
    if console is not None and layers is not None:
        from display import print_send_line

        print_send_line(console, iface, len(raw_packet_bytes), layers)
    else:
        print(f"\n[发包] 已通过接口 {iface} 发送 {len(raw_packet_bytes)} 字节")

    t.join(timeout=timeout + 1.0)
    t1 = time.perf_counter()
    elapsed_ms = (t1 - t0) * 1000.0
    try:
        sock.close()
    except OSError:
        pass

    if responses:
        return responses[0], elapsed_ms
    return None, elapsed_ms
