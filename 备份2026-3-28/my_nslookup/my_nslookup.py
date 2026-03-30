#!/usr/bin/env python3
"""my_nslookup 单文件可执行版：链路层注入 DNS 查询、捕获应答、写 pcap。
合并自：utils / packet_builder / display / dns_parser / packet_sender / pcap_writer / main
"""
from __future__ import annotations

import argparse
import fcntl
import os
import random
import socket
import struct
import sys
import threading
import time
from typing import Iterable

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from scapy.all import ARP, DNS, Ether, UDP, raw, sendp, sniff, srp, wrpcap

# ============================================================================
# utils
# ============================================================================


def get_local_ip(iface: str = "eth0") -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("256s", iface.encode()[:15].ljust(256, b"\x00"))
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, ifreq)[20:24])
    finally:
        s.close()


def get_local_mac(iface: str = "eth0") -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("256s", iface.encode()[:15].ljust(256, b"\x00"))
        info = fcntl.ioctl(s.fileno(), 0x8927, ifreq)
    finally:
        s.close()
    return ":".join("%02x" % b for b in info[18:24])


def get_default_gateway() -> str | None:
    try:
        with open("/proc/net/route") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    return socket.inet_ntoa(struct.pack("<I", int(parts[2], 16)))
    except OSError:
        pass
    return None


def get_gateway_mac(gateway_ip: str) -> str | None:
    if not gateway_ip:
        return None
    try:
        arp = ARP(pdst=gateway_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        ans, _ = srp(ether / arp, timeout=3, verbose=False)
        if ans:
            return ans[0][1].hwsrc
    except Exception:
        pass
    return None

# ============================================================================
# packet_builder
# ============================================================================

DNS_QUERY_FLAGS = 0x0100


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def encode_dns_name(domain: str) -> bytes:
    encoded = b""
    for part in domain.rstrip(".").split("."):
        encoded += bytes([len(part)]) + part.encode()
    encoded += b"\x00"
    return encoded


def build_dns_query(domain: str, qtype: int = 1) -> tuple[bytes, int]:
    transaction_id = random.randint(0, 65535)
    flags = DNS_QUERY_FLAGS
    qdcount = 1
    header = struct.pack(
        "!HHHHHH", transaction_id, flags, qdcount, 0, 0, 0
    )
    question = encode_dns_name(domain)
    question += struct.pack("!HH", qtype, 1)
    return header + question, transaction_id


def build_udp(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes
) -> bytes:
    length = 8 + len(payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo_header = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack("!BBH", 0, 17, length)
    )
    chk = checksum(pseudo_header + udp_header + payload)
    return struct.pack("!HHHH", src_port, dst_port, length, chk)


def build_ip(src_ip: str, dst_ip: str, payload: bytes, proto: int = 17) -> bytes:
    version_ihl = (4 << 4) | 5
    tos = 0
    total_length = 20 + len(payload)
    ip_id = random.randint(0, 65535)
    flags_offset = 0x4000
    ttl = 64
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        ip_id,
        flags_offset,
        ttl,
        proto,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    chk = checksum(ip_header)
    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        ip_id,
        flags_offset,
        ttl,
        proto,
        chk,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )


def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def build_ethernet(
    src_mac: str,
    dst_mac: str,
    payload: bytes,
    ether_type: int = 0x0800,
) -> bytes:
    return mac_to_bytes(dst_mac) + mac_to_bytes(src_mac) + struct.pack(
        "!H", ether_type
    ) + payload



# ============================================================================
# display (终端 UI)
# ============================================================================

# 摘要与会话
LAYER_SUMMARY = "summary"
# 请求路径（与 PDF「自行构造并打印各层」对应）
LAYER_ETH = "eth"
LAYER_IP = "ip"
LAYER_UDP = "udp"
LAYER_DNS = "dns"
# 响应路径（与 PDF「响应包各层」对应）
LAYER_RESP_ETH = "resp_eth"
LAYER_RESP_IP = "resp_ip"
LAYER_RESP_UDP = "resp_udp"
LAYER_RESP_DNS = "resp_dns"

LAYER_ALIASES = {
    "链路": LAYER_ETH,
    "以太网": LAYER_ETH,
    "网络": LAYER_IP,
    "传输": LAYER_UDP,
    "应答": "resp",
    "响应": "resp",
}


def make_console(*, no_color: bool = False, soft_wrap: bool = True) -> Console:
    return Console(soft_wrap=soft_wrap, no_color=no_color, highlight=False)


def normalize_domain(raw: str) -> str:
    """接受域名或带 http(s)://、路径、端口的「网址」输入，提取主机名。"""
    s = raw.strip()
    if not s:
        return s
    lower = s.lower()
    for pfx in ("http://", "https://"):
        if lower.startswith(pfx):
            s = s[len(pfx) :]
            lower = s.lower()
            break
    s = s.split("/")[0].split("?")[0]
    if "@" in s:
        s = s.rsplit("@", 1)[-1]
    if ":" in s and not s.startswith("["):
        host, _, rest = s.partition(":")
        if rest.isdigit() or rest == "":
            s = host
    return s.strip(" .") or raw.strip()


def normalize_show(show: str) -> set[str]:
    """
    解析 --show：逗号分隔。
    关键字：all, summary, eth, ip, udp, dns,
           resp 或 response（展开为 resp_eth,resp_ip,resp_udp,resp_dns）,
           req 或 request（展开为 eth,ip,udp,dns）。
    中文别名：链路→eth，网络→ip，传输→udp，应答/响应→resp。
    """
    if not show or not str(show).strip():
        return {"all"}
    parts: list[str] = []
    for seg in str(show).replace("，", ",").split(","):
        t = seg.strip().lower()
        if not t:
            continue
        if t == "all":
            return {"all"}
        t = LAYER_ALIASES.get(t, t)
        if t in ("resp", "response", "应答", "响应"):
            parts.extend(
                [LAYER_RESP_ETH, LAYER_RESP_IP, LAYER_RESP_UDP, LAYER_RESP_DNS]
            )
        elif t in ("req", "request", "请求"):
            parts.extend([LAYER_ETH, LAYER_IP, LAYER_UDP, LAYER_DNS])
        else:
            parts.append(t)
    if not parts:
        return {"all"}
    return set(parts)


def layer_visible(name: str, layers: set[str]) -> bool:
    return "all" in layers or name in layers


def any_request_layer(layers: set[str]) -> bool:
    return "all" in layers or any(
        x in layers for x in (LAYER_ETH, LAYER_IP, LAYER_UDP, LAYER_DNS)
    )


def any_response_layer(layers: set[str]) -> bool:
    return "all" in layers or any(
        x in layers
        for x in (
            LAYER_RESP_ETH,
            LAYER_RESP_IP,
            LAYER_RESP_UDP,
            LAYER_RESP_DNS,
        )
    )


def print_title(console: Console, subtitle: str = "") -> None:
    from rich.text import Text

    title = Text("my_nslookup", style="bold cyan")
    sub = Text(f"  {subtitle}" if subtitle else "", style="dim")
    console.print(
        Panel.fit(title + sub, border_style="cyan", box=box.DOUBLE_EDGE)
    )


def print_session_summary(
    console: Console,
    *,
    domain: str,
    dns_server: str,
    src_ip: str,
    src_mac: str,
    gw_ip: str | None,
    gw_mac: str | None,
    src_port: int,
    iface: str,
    qtype_name: str,
    layers: set[str],
) -> None:
    if not layer_visible(LAYER_SUMMARY, layers):
        return
    t = Table(
        title="会话参数",
        box=box.ROUNDED,
        show_header=False,
        title_style="bold green",
    )
    t.add_column("项", style="dim", width=14)
    t.add_column("值", style="white")
    t.add_row("查询域名", domain)
    t.add_row("DNS 服务器", dns_server)
    t.add_row("记录类型", qtype_name)
    t.add_row("网卡", iface)
    t.add_row("本机 IPv4", src_ip)
    t.add_row("本机 MAC", src_mac)
    t.add_row("默认网关", gw_ip or "—")
    t.add_row("下一跳 MAC", gw_mac or "—")
    t.add_row("UDP 源端口", str(src_port))
    console.print(t)
    console.print()


def _kv_table(title: str, rows: Iterable[tuple[str, str]], style: str = "blue") -> Table:
    tb = Table(
        title=title,
        box=box.MINIMAL_DOUBLE_HEAD,
        show_header=True,
        header_style=f"bold {style}",
        title_style=f"bold {style}",
    )
    tb.add_column("字段", style="dim", no_wrap=True)
    tb.add_column("值", style="white")
    for k, v in rows:
        tb.add_row(k, v)
    return tb


def ipv4_header_kv_rows(ip_header: bytes) -> list[tuple[str, str]]:
    """从 IPv4 首部前 20 字节解析各字段（与实验演示表一致）。"""
    h = ip_header[:20].ljust(20, b"\x00")
    vihl = h[0]
    ver = (vihl >> 4) & 0xF
    ihl = (vihl & 0x0F) * 4
    tos = h[1]
    total_len = struct.unpack("!H", h[2:4])[0]
    ident = struct.unpack("!H", h[4:6])[0]
    ff = struct.unpack("!H", h[6:8])[0]
    ttl = h[8]
    proto = h[9]
    chk = struct.unpack("!H", h[10:12])[0]
    src_ip = socket.inet_ntoa(h[12:16])
    dst_ip = socket.inet_ntoa(h[16:20])
    proto_name = "UDP" if proto == 17 else ("TCP" if proto == 6 else str(proto))
    return [
        ("版本", str(ver)),
        ("首部长度 (IHL)", f"{ihl} 字节"),
        ("TOS", f"0x{tos:02X}"),
        ("总长度", f"{total_len} 字节"),
        ("标识 (Identification)", f"0x{ident:04X}"),
        ("标志与片偏移", f"0x{ff:04X}"),
        ("TTL", str(ttl)),
        ("协议", f"{proto} ({proto_name})"),
        ("首部校验和", f"0x{chk:04X}"),
        ("源地址", src_ip),
        ("目的地址", dst_ip),
    ]


def dns_flags_kv_rows(flags: int) -> list[tuple[str, str]]:
    """DNS Flags 按位展开（查询/应答通用）。"""
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    z = (flags >> 4) & 0x7
    rcode = flags & 0xF
    rcode_txt = (
        "无错误"
        if rcode == 0
        else ("格式错误" if rcode == 1 else ("服务器失败" if rcode == 2 else f"码 {rcode}"))
    )
    return [
        ("Flags (原始值)", f"0x{flags:04X}"),
        ("  QR", f"{qr} ({'应答' if qr else '查询'})"),
        ("  Opcode", str(opcode)),
        ("  AA", str(aa)),
        ("  TC", str(tc)),
        ("  RD", str(rd)),
        ("  RA", str(ra)),
        ("  Z", str(z)),
        ("  RCODE", f"{rcode} ({rcode_txt})"),
    ]


def print_dns_query_layer(
    console: Console,
    *,
    domain: str,
    qtype: int,
    transaction_id: int,
    dns_flags: int,
    layers: set[str],
) -> None:
    if not layer_visible(LAYER_DNS, layers):
        return
    qtype_map = {
        1: "A",
        28: "AAAA",
        5: "CNAME",
        2: "NS",
        15: "MX",
        16: "TXT",
    }
    rows: list[tuple[str, str]] = [
        ("Transaction ID", f"0x{transaction_id:04X}"),
    ]
    rows.extend(dns_flags_kv_rows(dns_flags))
    rows.extend(
        [
            ("Questions", "1"),
            ("Answer RRs", "0"),
            ("Authority RRs", "0"),
            ("Additional RRs", "0"),
            ("QNAME", domain),
            ("QTYPE", qtype_map.get(qtype, str(qtype))),
            ("QCLASS", "IN (1)"),
        ]
    )
    console.print(
        Panel(
            _kv_table("DNS 查询（应用层 · 请求）", rows, style="magenta"),
            border_style="magenta",
        )
    )
    console.print()


def print_udp_layer(
    console: Console,
    *,
    src_port: int,
    dst_port: int,
    length: int,
    checksum_val: int,
    layers: set[str],
) -> None:
    if not layer_visible(LAYER_UDP, layers):
        return
    payload_len = max(0, length - 8)
    rows = [
        ("源端口", str(src_port)),
        ("目的端口", str(dst_port)),
        ("UDP 总长度", f"{length} 字节"),
        ("UDP 载荷长度", f"{payload_len} 字节"),
        ("校验和", f"0x{checksum_val:04X}"),
    ]
    console.print(
        Panel(
            _kv_table("UDP（传输层 · 请求）", rows, style="yellow"),
            border_style="yellow",
        )
    )
    console.print()


def print_ip_layer(
    console: Console,
    *,
    ip_header: bytes,
    layers: set[str],
) -> None:
    if not layer_visible(LAYER_IP, layers):
        return
    rows = ipv4_header_kv_rows(ip_header)
    console.print(
        Panel(
            _kv_table("IPv4（网络层 · 请求）", rows, style="green"),
            border_style="green",
        )
    )
    console.print()


def print_ethernet_layer(
    console: Console,
    *,
    src_mac: str,
    dst_mac: str,
    ether_type: int,
    layers: set[str],
) -> None:
    if not layer_visible(LAYER_ETH, layers):
        return
    rows = [
        ("目的 MAC", dst_mac),
        ("源 MAC", src_mac),
        ("类型", f"0x{ether_type:04X} (IPv4)"),
    ]
    console.print(
        Panel(
            _kv_table("以太网帧（链路层 · 请求）", rows, style="blue"),
            border_style="blue",
        )
    )
    console.print()


def print_outgoing_request_stack(
    console: Console,
    layers: set[str],
    order: str,
    *,
    src_mac: str,
    dst_mac: str,
    ether_type: int,
    ip_header: bytes,
    dns_flags: int,
    src_port: int,
    dst_port: int,
    udp_len: int,
    udp_chk: int,
    domain: str,
    qtype: int,
    transaction_id: int,
) -> None:
    """
    打印请求侧各层。order=osi：链路→网络→传输→DNS；
    order=reverse：DNS→传输→网络→链路（与栈自顶向下构造一致）。
    """
    order = (order or "osi").lower()
    if order not in ("osi", "reverse"):
        order = "osi"

    def _eth() -> None:
        print_ethernet_layer(
            console,
            src_mac=src_mac,
            dst_mac=dst_mac,
            ether_type=ether_type,
            layers=layers,
        )

    def _ip() -> None:
        print_ip_layer(
            console,
            ip_header=ip_header,
            layers=layers,
        )

    def _udp() -> None:
        print_udp_layer(
            console,
            src_port=src_port,
            dst_port=dst_port,
            length=udp_len,
            checksum_val=udp_chk,
            layers=layers,
        )

    def _dns() -> None:
        print_dns_query_layer(
            console,
            domain=domain,
            qtype=qtype,
            transaction_id=transaction_id,
            dns_flags=dns_flags,
            layers=layers,
        )

    seq = [_eth, _ip, _udp, _dns]
    if order == "reverse":
        seq.reverse()
    for fn in seq:
        fn()


def print_request_size(
    console: Console, nbytes: int, layers: set[str]
) -> None:
    if not any_request_layer(layers):
        return
    console.print(
        Panel(
            f"[bold]请求以太网帧总长度[/bold]  [cyan]{nbytes}[/cyan] 字节",
            border_style="dim",
            box=box.SIMPLE,
        )
    )
    console.print()


def print_send_line(
    console: Console, iface: str, nbytes: int, layers: set[str]
) -> None:
    if not any_request_layer(layers):
        return
    console.print(
        f"[green]✓[/green] 已通过接口 [bold]{iface}[/bold] 注入 L2 数据包 "
        f"（[dim]{nbytes} 字节[/dim]）"
    )
    console.print()


def _mac_fmt(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def print_response_frame_layers(
    console: Console,
    raw: bytes,
    layers: set[str],
    *,
    order: str = "osi",
) -> None:
    """
    从完整应答帧打印链路 / 网络 / 传输层。
    order=osi：以太网 → IP → UDP（与线路上帧头顺序一致，默认）。
    order=reverse：UDP → IP → 以太网（自顶向下视角）。
    """
    if len(raw) < 14:
        return
    eth = raw[:14]
    dst_m = _mac_fmt(eth[0:6])
    src_m = _mac_fmt(eth[6:12])
    etype = struct.unpack("!H", eth[12:14])[0]

    def _eth() -> None:
        rows = [
            ("目的 MAC", dst_m),
            ("源 MAC", src_m),
            (
                "类型",
                f"0x{etype:04X} (IPv4)" if etype == 0x0800 else f"0x{etype:04X}",
            ),
        ]
        console.print(
            Panel(
                _kv_table("以太网帧（链路层 · 应答）", rows, style="blue"),
                border_style="blue",
            )
        )
        console.print()

    ip_off = 14
    ip_rows: list[tuple[str, str]] | None = None
    udp_rows: list[tuple[str, str]] | None = None

    if etype == 0x0800 and len(raw) >= 14 + 20:
        vihl = raw[ip_off]
        ihl = (vihl & 0x0F) * 4
        if ihl >= 20 and len(raw) >= ip_off + ihl:
            ip_hdr = raw[ip_off : ip_off + ihl]
            ip_rows = ipv4_header_kv_rows(ip_hdr[:20])
            proto = ip_hdr[9]
            if proto == 17:
                udp_off = ip_off + ihl
                if len(raw) >= udp_off + 8:
                    sport, dport, ulen, uchk = struct.unpack(
                        "!HHHH", raw[udp_off : udp_off + 8]
                    )
                    plen = max(0, ulen - 8)
                    udp_rows = [
                        ("源端口", str(sport)),
                        ("目的端口", str(dport)),
                        ("UDP 总长度", f"{ulen} 字节"),
                        ("UDP 载荷长度", f"{plen} 字节"),
                        ("校验和", f"0x{uchk:04X}"),
                    ]

    def _ip() -> None:
        if not ip_rows:
            return
        console.print(
            Panel(
                _kv_table("IPv4（网络层 · 应答）", ip_rows, style="green"),
                border_style="green",
            )
        )
        console.print()

    def _udp() -> None:
        if not udp_rows:
            return
        console.print(
            Panel(
                _kv_table("UDP（传输层 · 应答）", udp_rows, style="yellow"),
                border_style="yellow",
            )
        )
        console.print()

    segments: list[tuple[str, object]] = []
    if layer_visible(LAYER_RESP_ETH, layers):
        segments.append(("eth", _eth))
    if layer_visible(LAYER_RESP_IP, layers) and ip_rows:
        segments.append(("ip", _ip))
    if layer_visible(LAYER_RESP_UDP, layers) and udp_rows:
        segments.append(("udp", _udp))

    if order == "reverse":
        segments.reverse()

    for _, fn in segments:
        fn()


def print_timeout(console: Console) -> None:
    console.print(
        Panel(
            "[yellow]未在超时时间内收到匹配的 DNS 应答。[/yellow]\n"
            "请检查：DNS 是否可达、过滤器、接口名、[dim]是否具备抓包权限（如 sudo）[/dim]",
            title="超时",
            border_style="yellow",
        )
    )


def show_help_layers(console: Console) -> None:
    t = Table(
        title="--show 分层说明（可逗号组合）",
        box=box.SIMPLE_HEAVY,
        title_style="bold",
    )
    t.add_column("关键字", style="cyan", no_wrap=True)
    t.add_column("含义", style="white")
    t.add_row("all", "全部（默认）")
    t.add_row("summary", "会话摘要表")
    t.add_row("eth, ip, udp, dns", "请求：链路 → 网络 → 传输 → DNS 查询")
    t.add_row("resp 或 response", "应答：四层 + DNS 解析（等价于四个 resp_*）")
    t.add_row("resp_eth, resp_ip, resp_udp", "仅应答帧的链路 / 网络 / 传输")
    t.add_row("resp_dns", "仅 DNS 应答解析（头部 + 各 RR）")
    t.add_row("request", "缩写 req：eth+ip+udp+dns 请求侧")
    console.print(t)
    console.print()
    o = Table(
        title="--order 打印顺序",
        box=box.SIMPLE_HEAVY,
        title_style="bold",
    )
    o.add_column("值", style="cyan", no_wrap=True)
    o.add_column("含义", style="white")
    o.add_row(
        "osi",
        "自链路层→应用层（与线路上帧头顺序一致，默认；应答：以太网→IP→UDP→DNS）",
    )
    o.add_row(
        "reverse",
        "自应用层→链路层（与协议栈自顶向下填写顺序一致；应答：DNS→UDP→IP→以太网）",
    )
    console.print(o)


def print_phase_rule(console: Console, title: str, *, style: str = "cyan") -> None:
    from rich.rule import Rule

    console.print()
    console.print(Rule(title, style=style))
    console.print()

# ============================================================================
# dns_parser
# ============================================================================


def decode_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    offset_after_jump = 0
    jumps = 0

    while offset < len(data) and jumps < 12:
        length = data[offset]
        if length == 0:
            if not jumped:
                offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                offset_after_jump = offset + 2
            jumped = True
            jumps += 1
            offset = ptr
            continue
        offset += 1
        labels.append(
            data[offset : offset + length].decode("utf-8", errors="replace")
        )
        offset += length

    name = ".".join(labels)
    if jumped:
        return name, offset_after_jump
    return name, offset


def _parse_txt_rdata(rdata: bytes) -> str:
    parts: list[str] = []
    pos = 0
    while pos < len(rdata):
        ln = rdata[pos]
        pos += 1
        parts.append(rdata[pos : pos + ln].decode("utf-8", errors="replace"))
        pos += ln
    return " ".join(parts)


def _parse_one_rr(
    data: bytes, offset: int, rtype_map: dict[int, str]
) -> tuple[dict | None, int]:
    if offset >= len(data):
        return None, offset
    name, offset = decode_dns_name(data, offset)
    if offset + 10 > len(data):
        return None, offset
    rtype, rclass, ttl, rdlength = struct.unpack(
        "!HHIH", data[offset : offset + 10]
    )
    offset += 10
    if offset + rdlength > len(data):
        return None, offset - 10
    rdata = data[offset : offset + rdlength]
    rdata_off = offset
    offset += rdlength

    rtype_str = rtype_map.get(rtype, str(rtype))
    value: str

    if rtype == 1 and rdlength == 4:
        value = socket.inet_ntoa(rdata)
    elif rtype == 28 and rdlength == 16:
        value = socket.inet_ntop(socket.AF_INET6, rdata)
    elif rtype in (5, 2, 39):
        value, _ = decode_dns_name(data, rdata_off)
    elif rtype == 15 and rdlength >= 2:
        pref = struct.unpack("!H", rdata[:2])[0]
        mx_name, _ = decode_dns_name(data, rdata_off + 2)
        value = f"优先级={pref} 主机={mx_name}"
    elif rtype == 16:
        value = _parse_txt_rdata(rdata)
    else:
        value = rdata.hex()

    rec = {
        "name": name,
        "type": rtype_str,
        "value": value,
        "ttl": ttl,
        "rr_class": rclass,
        "rr_class_name": "IN" if rclass == 1 else str(rclass),
        "rdlength": rdlength,
    }
    return rec, offset


def parse_dns_response(
    data: bytes,
    *,
    console: Console | None = None,
    layers: set[str] | None = None,
    merge_rr_sections: bool = True,
) -> list[dict]:
    """
    解析 DNS 应答；在 layer 包含 resp_dns 或 all 时用 Rich 打印。
    merge_rr_sections=True 时合并 Answer/Authority/Additional 为一张表（含「段」列）。
    """
    layers = layers or {"all"}
    console = console or Console(highlight=False)
    rtype_map = {
        1: "A",
        28: "AAAA",
        5: "CNAME",
        2: "NS",
        15: "MX",
        16: "TXT",
    }
    show = layer_visible(LAYER_RESP_DNS, layers)

    if len(data) < 12:
        if show:
            console.print(
                Panel("[red]DNS 载荷过短[/red]", title="错误", border_style="red")
            )
        return []

    header = struct.unpack("!HHHHHH", data[:12])
    txid, flags, qdcount, ancount, nscount, arcount = header

    if show:
        ht = Table(
            title="DNS 应答头部（应用层 · 应答）",
            box=box.MINIMAL_DOUBLE_HEAD,
            show_header=True,
            header_style="bold magenta",
            title_style="bold magenta",
        )
        ht.add_column("字段", style="dim", no_wrap=True)
        ht.add_column("值", style="white")
        ht.add_row("Transaction ID", f"0x{txid:04X}")
        for k, v in dns_flags_kv_rows(flags):
            ht.add_row(k, v)
        ht.add_row("Questions", str(qdcount))
        ht.add_row("Answer RRs", str(ancount))
        ht.add_row("Authority RRs", str(nscount))
        ht.add_row("Additional RRs", str(arcount))
        console.print(Panel(ht, border_style="magenta"))
        console.print()

    offset = 12
    for _ in range(qdcount):
        _, offset = decode_dns_name(data, offset)
        offset += 4

    all_records: list[dict] = []

    def collect_section(
        count: int, section_label: str
    ) -> tuple[list[dict], int]:
        nonlocal offset
        out: list[dict] = []
        for _ in range(count):
            rec, offset = _parse_one_rr(data, offset, rtype_map)
            if rec is None:
                break
            rec["section"] = section_label
            out.append(rec)
            all_records.append(rec)
        return out, offset

    if merge_rr_sections:
        merged_rows: list[dict] = []
        for count, label in (
            (ancount, "Answer"),
            (nscount, "Authority"),
            (arcount, "Additional"),
        ):
            if count == 0:
                continue
            sec_recs, _ = collect_section(count, label)
            merged_rows.extend(sec_recs)
        if show and merged_rows:
            mt = Table(
                title="DNS 资源记录（RR）全部信息",
                box=box.SIMPLE,
                show_lines=True,
                header_style="bold cyan",
                title_style="bold cyan",
            )
            mt.add_column("段", style="dim", no_wrap=True)
            mt.add_column("类型", style="yellow", no_wrap=True)
            mt.add_column("名称", style="white")
            mt.add_column("Class", style="dim", no_wrap=True)
            mt.add_column("TTL", justify="right", style="dim")
            mt.add_column("RDLength", justify="right", style="dim")
            mt.add_column("数据 (RDATA)", style="green")
            for rec in merged_rows:
                mt.add_row(
                    rec.get("section", ""),
                    rec["type"],
                    rec["name"],
                    rec.get("rr_class_name", "—"),
                    str(rec["ttl"]),
                    str(rec.get("rdlength", "—")),
                    str(rec["value"]),
                )
            console.print(Panel(mt, border_style="cyan"))
            console.print()
        return all_records

    def dump_section(count: int, title: str) -> None:
        nonlocal offset
        if count == 0:
            return
        section_recs: list[dict] = []
        for _ in range(count):
            rec, offset = _parse_one_rr(data, offset, rtype_map)
            if rec is None:
                break
            all_records.append(rec)
            section_recs.append(rec)
        if show and section_recs:
            sec = Table(
                title=title,
                box=box.SIMPLE,
                show_lines=True,
                header_style="bold cyan",
                title_style="bold cyan",
            )
            sec.add_column("类型", style="yellow", no_wrap=True)
            sec.add_column("名称", style="white")
            sec.add_column("Class", style="dim", no_wrap=True)
            sec.add_column("TTL", justify="right", style="dim")
            sec.add_column("RDLength", justify="right", style="dim")
            sec.add_column("数据 (RDATA)", style="green")
            for rec in section_recs:
                sec.add_row(
                    rec["type"],
                    rec["name"],
                    rec.get("rr_class_name", "—"),
                    str(rec["ttl"]),
                    str(rec.get("rdlength", "—")),
                    str(rec["value"]),
                )
            console.print(Panel(sec, border_style="cyan"))
            console.print()

    dump_section(ancount, "Answer 记录")
    dump_section(nscount, "Authority 记录")
    dump_section(arcount, "Additional 记录")

    return all_records

# ============================================================================
# packet_sender
# ============================================================================


def send_and_receive(
    raw_packet_bytes: bytes,
    iface: str,
    src_port: int,
    transaction_id: int,
    timeout: float = 5.0,
    *,
    console: "Console | None" = None,
    layers: set[str] | None = None,
):
    """
    先占住 UDP 源端口，避免内核因“无监听端口”向 DNS 回 ICMP Port Unreachable；
    在线程中 sniff，主线程 sendp 发以太帧；按 Transaction ID 匹配应答。
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
    sendp(pkt, iface=iface, verbose=False)
    if console is not None and layers is not None:
        print_send_line(console, iface, len(raw_packet_bytes), layers)
    else:
        print(f"\n[发包] 已通过接口 {iface} 发送 {len(raw_packet_bytes)} 字节")

    t.join(timeout=timeout + 1.0)
    try:
        sock.close()
    except OSError:
        pass

    return responses[0] if responses else None

# ============================================================================
# pcap_writer
# ============================================================================


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

# ============================================================================
# main
# ============================================================================



def _interactive_prompts(defaults: dict) -> dict:
    from rich.prompt import Prompt

    print_title(defaults["console"], "交互模式 / Interactive")
    c = defaults["console"]
    dns = Prompt.ask(
        "DNS 服务器 IP",
        default=defaults.get("dns_server") or "8.8.8.8",
        console=c,
    )
    raw_name = Prompt.ask(
        "域名或网址（可含 http(s)://）",
        default=defaults.get("domain") or "example.com",
        console=c,
    )
    domain = normalize_domain(raw_name)
    qtype = Prompt.ask(
        "记录类型",
        default=defaults.get("qtype") or "A",
        choices=["A", "AAAA", "CNAME", "NS", "MX", "TXT"],
        show_choices=True,
        console=c,
    )
    iface = Prompt.ask(
        "网卡接口名",
        default=defaults.get("iface") or "eth0",
        console=c,
    )
    show = Prompt.ask(
        "显示哪些层（逗号分隔，或 all）",
        default=defaults.get("show") or "all",
        console=c,
    )
    out = Prompt.ask(
        "pcap 输出路径",
        default=defaults.get("output") or "capture.pcap",
        console=c,
    )
    order = Prompt.ask(
        "各层打印顺序",
        default=defaults.get("order") or "osi",
        choices=["osi", "reverse"],
        show_choices=True,
        console=c,
    )
    return {
        "dns_server": dns.strip(),
        "domain": domain,
        "qtype": qtype,
        "iface": iface.strip(),
        "show": show.strip(),
        "output": out.strip(),
        "order": order.strip().lower(),
    }


def run_once(
    *,
    dns_server: str,
    domain: str,
    qtype_name: str,
    src_mac: str | None,
    gw_mac: str | None,
    src_ip: str | None,
    src_port: int | None,
    iface: str,
    output: str,
    layers: set[str],
    console,
    order: str = "osi",
) -> None:
    qtype_map = {"A": 1, "AAAA": 28, "CNAME": 5, "NS": 2, "MX": 15, "TXT": 16}
    qtype = qtype_map[qtype_name]

    src_port = (
        src_port
        if src_port is not None
        else random.randint(32768, 65535)
    )
    src_ip = src_ip or get_local_ip(iface)
    src_mac = src_mac or get_local_mac(iface)
    gw_ip = get_default_gateway()
    gw_mac = gw_mac or (get_gateway_mac(gw_ip) if gw_ip else None)

    print_title(console)
    print_session_summary(
        console,
        domain=domain,
        dns_server=dns_server,
        src_ip=src_ip,
        src_mac=src_mac,
        gw_ip=gw_ip,
        gw_mac=gw_mac,
        src_port=src_port,
        iface=iface,
        qtype_name=qtype_name,
        layers=layers,
    )

    if not gw_mac:
        console.print(
            "[red]错误:[/red] 无法解析网关 MAC，请检查网络或使用 [bold]--gw-mac[/bold]。"
        )
        sys.exit(1)

    dns_payload, txid = build_dns_query(domain, qtype)

    udp_header = build_udp(src_ip, dns_server, src_port, 53, dns_payload)
    udp_full = udp_header + dns_payload
    sp, dp, ln, chk = struct.unpack("!HHHH", udp_header)

    ip_header = build_ip(src_ip, dns_server, udp_full)

    eth_frame = build_ethernet(src_mac, gw_mac, ip_header + udp_full)

    ord_ = (order or "osi").lower()
    if ord_ not in ("osi", "reverse"):
        ord_ = "osi"

    if any_request_layer(layers):
        print_phase_rule(
            console,
            "① 发送请求帧 — osi：链路→网络→传输→应用；reverse：应用→传输→网络→链路",
        )
        console.print("[dim]=== Sending DNS Query ===[/dim]\n")
    print_outgoing_request_stack(
        console,
        layers,
        ord_,
        src_mac=src_mac,
        dst_mac=gw_mac,
        ether_type=0x0800,
        ip_header=ip_header,
        dns_flags=DNS_QUERY_FLAGS,
        src_port=sp,
        dst_port=dp,
        udp_len=ln,
        udp_chk=chk,
        domain=domain,
        qtype=qtype,
        transaction_id=txid,
    )
    print_request_size(console, len(eth_frame), layers)

    response = send_and_receive(
        eth_frame,
        iface,
        src_port,
        txid,
        timeout=5.0,
        console=console,
        layers=layers,
    )

    out_path = output
    if not os.path.isabs(out_path):
        out_path = os.path.join(os.getcwd(), out_path)

    pcap_list: list[bytes] = [eth_frame]
    if response:
        resp_raw = raw(response)
        pcap_list.append(resp_raw)
        eth_len = 14
        ihl = (resp_raw[eth_len] & 0x0F) * 4
        dns_data = resp_raw[eth_len + ihl + 8 :]

        if any_response_layer(layers):
            print_phase_rule(
                console,
                "② 接收应答帧 — osi：链路→网络→传输→DNS；reverse：DNS→传输→网络→链路",
            )
            console.print("[dim]=== Received DNS Response ===[/dim]\n")

        if ord_ == "osi":
            if any_response_layer(layers):
                print_response_frame_layers(
                    console, resp_raw, layers, order="osi"
                )
            parse_dns_response(
                dns_data, console=console, layers=layers, merge_rr_sections=True
            )
        else:
            parse_dns_response(
                dns_data, console=console, layers=layers, merge_rr_sections=True
            )
            if any_response_layer(layers):
                print_response_frame_layers(
                    console, resp_raw, layers, order="reverse"
                )
    else:
        print_timeout(console)

    save_pcap(pcap_list, out_path, console=console)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="my_nslookup — 自定义 DNS 解析（链路层注入 + 抓包 + pcap）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 my_nslookup.py 8.8.8.8 www.baidu.com
  python3 my_nslookup.py 8.8.8.8 https://www.qq.com/ --show eth,ip,dns
  python3 my_nslookup.py -i
  python3 my_nslookup.py 114.114.114.114 example.com -S resp --no-color
  python3 my_nslookup.py 8.8.8.8 example.com --order reverse

--show 分层见: python3 my_nslookup.py --show-help
        """.strip(),
    )
    parser.add_argument(
        "dns_server",
        nargs="?",
        default=None,
        help="DNS 服务器 IPv4（交互模式可省略）",
    )
    parser.add_argument(
        "domain",
        nargs="?",
        default=None,
        help="域名；也可写带 http(s):// 的网址，会自动取主机名",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="交互式输入 DNS、域名、记录类型、显示层等",
    )
    parser.add_argument(
        "-S",
        "--show",
        dest="show_layers",
        default="all",
        metavar="LAYERS",
        help="逗号分隔显示层：summary,eth,ip,udp,dns,resp,resp_eth,... 默认 all",
    )
    parser.add_argument(
        "--show-help",
        action="store_true",
        help="说明 --show 各关键字含义后退出",
    )
    parser.add_argument("--src-mac", help="本机 MAC（默认 ioctl）")
    parser.add_argument("--gw-mac", help="下一跳 MAC（默认 ARP）")
    parser.add_argument("--src-ip", help="本机 IPv4（默认网卡）")
    parser.add_argument(
        "--src-port",
        type=int,
        default=None,
        help="UDP 源端口（默认随机）",
    )
    parser.add_argument("--iface", default="eth0", help="网络接口")
    parser.add_argument(
        "--type",
        default="A",
        choices=["A", "AAAA", "CNAME", "NS", "MX", "TXT"],
        help="DNS 查询类型",
    )
    parser.add_argument(
        "--output",
        default="capture.pcap",
        help="pcap 输出路径",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="禁用 ANSI 颜色（重定向到文件时更干净）",
    )
    parser.add_argument(
        "--order",
        choices=("osi", "reverse"),
        default="osi",
        help="各层打印顺序：osi=链路→应用（默认）；reverse=应用→链路",
    )
    args = parser.parse_args()

    console = make_console(no_color=args.no_color)

    if args.show_help:
        show_help_layers(console)
        raise SystemExit(0)

    layers = normalize_show(args.show_layers)
    dns_server = args.dns_server
    domain_in = args.domain
    qtype = args.type
    iface = args.iface
    output = args.output
    order = args.order

    if args.interactive:
        filled = _interactive_prompts(
            {
                "console": console,
                "dns_server": dns_server,
                "domain": domain_in,
                "qtype": qtype,
                "iface": iface,
                "show": args.show_layers,
                "output": output,
                "order": args.order,
            }
        )
        dns_server = filled["dns_server"]
        domain_in = filled["domain"]
        qtype = filled["qtype"]
        iface = filled["iface"]
        layers = normalize_show(filled["show"])
        output = filled["output"]
        order = filled.get("order", args.order)
    elif not dns_server or not domain_in:
        console.print(
            "[red]请提供:[/red] DNS 服务器 IP 与域名，或使用 [bold]-i[/bold] 进入交互模式。"
        )
        parser.print_help()
        raise SystemExit(2)

    domain = normalize_domain(domain_in)

    run_once(
        dns_server=dns_server.strip(),
        domain=domain,
        qtype_name=qtype,
        src_mac=args.src_mac,
        gw_mac=args.gw_mac,
        src_ip=args.src_ip,
        src_port=args.src_port,
        iface=iface,
        output=output,
        layers=layers,
        console=console,
        order=order,
    )


if __name__ == "__main__":
    main()
