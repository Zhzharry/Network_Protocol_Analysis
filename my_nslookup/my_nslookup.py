#!/usr/bin/env python3
"""my_nslookup 单文件可执行版：链路层注入 DNS 查询、捕获应答、写 pcap。
合并自：utils / session_report / packet_builder / display / dns_parser / packet_sender / pcap_writer / main
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import random
import socket
import struct
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Iterable

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
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


def iface_exists(iface: str) -> bool:
    if not iface:
        return False
    return os.path.isdir(os.path.join("/sys/class/net", iface))


# ============================================================================
# session_report（结构化摘要 / 报告导出）
# ============================================================================


def summarize_dns_records(records: list[dict]) -> dict[str, Any]:
    answers = [r for r in records if r.get("section") == "Answer"]
    a_vals = [r["value"] for r in answers if r.get("type") == "A"]
    aaaa_vals = [r["value"] for r in answers if r.get("type") == "AAAA"]
    cname_hops = [
        f"{r['name']} → {r['value']}"
        for r in answers
        if r.get("type") == "CNAME"
    ]
    return {
        "total_rr": len(records),
        "answer_rr_count": len(answers),
        "ipv4_addresses": a_vals,
        "ipv6_addresses": aaaa_vals,
        "cname_hops": cname_hops,
    }


def build_json_payload(
    *,
    version: str,
    success: bool,
    domain: str,
    dns_server: str,
    qtype_name: str,
    iface: str,
    transaction_id: int,
    rtt_ms: float | None,
    records: list[dict],
    pcap_path: str,
    timeout: bool,
) -> dict[str, Any]:
    summ = summarize_dns_records(records) if records else {}
    return {
        "tool": "my_nslookup",
        "version": version,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "success": success and not timeout,
        "timeout": timeout,
        "query": {
            "domain": domain,
            "type": qtype_name,
            "dns_server": dns_server,
            "iface": iface,
        },
        "transaction_id": f"0x{transaction_id:04X}",
        "rtt_ms": round(rtt_ms, 3) if rtt_ms is not None else None,
        "record_count": len(records),
        "summary": summ,
        "pcap_path": pcap_path,
    }


def render_markdown_report(payload: dict[str, Any]) -> str:
    q = payload["query"]
    summ = payload.get("summary") or {}
    lines = [
        "# DNS 会话报告（my_nslookup）",
        "",
        f"- **生成时间（UTC）**: {payload.get('timestamp_utc', '')}",
        f"- **工具版本**: {payload.get('version', '')}",
        "",
        "## 查询参数",
        "",
        f"| 项目 | 值 |",
        f"|------|-----|",
        f"| 域名 | `{q.get('domain', '')}` |",
        f"| 记录类型 | {q.get('type', '')} |",
        f"| DNS 服务器 | `{q.get('dns_server', '')}` |",
        f"| 网卡 | `{q.get('iface', '')}` |",
        "",
        "## 结果",
        "",
        f"- **状态**: {'成功' if payload.get('success') else ('超时' if payload.get('timeout') else '失败')}",
    ]
    rtt = payload.get("rtt_ms")
    if rtt is not None:
        rtt_label = "等待耗时" if payload.get("timeout") else "往返时延 (RTT)"
        lines.append(f"- **{rtt_label}**: {rtt} ms")
    lines.append(f"- **Transaction ID**: {payload.get('transaction_id', '')}")
    lines.append(f"- **资源记录条数**: {payload.get('record_count', 0)}")
    lines.append(f"- **pcap 路径**: `{payload.get('pcap_path', '')}`")
    lines.extend(["", "## 解析摘要", ""])
    if summ.get("ipv4_addresses"):
        lines.append("### IPv4（A）")
        for ip in summ["ipv4_addresses"]:
            lines.append(f"- `{ip}`")
        lines.append("")
    if summ.get("ipv6_addresses"):
        lines.append("### IPv6（AAAA）")
        for ip in summ["ipv6_addresses"]:
            lines.append(f"- `{ip}`")
        lines.append("")
    if summ.get("cname_hops"):
        lines.append("### CNAME 链（Answer 段）")
        for hop in summ["cname_hops"]:
            lines.append(f"- {hop}")
        lines.append("")
    if not summ.get("ipv4_addresses") and not summ.get("cname_hops") and not summ.get(
        "ipv6_addresses"
    ):
        lines.append("*（无 IPv4/IPv6/CNAME 摘要，或查询未返回应答记录）*")
        lines.append("")
    lines.append("---")
    lines.append("*由 `my_nslookup --export-report` 自动生成。*")
    lines.append("")
    return "\n".join(lines)


def write_text_report(path: str, markdown: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(markdown)


# ============================================================================
# hexdump_fmt
# ============================================================================


def format_hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    if not data:
        return "（空）"
    lines: list[str] = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        hex_groups: list[str] = []
        for j in range(0, len(chunk), 8):
            octet = chunk[j : j + 8]
            hex_groups.append(" ".join(f"{b:02x}" for b in octet))
        hex_str = "  ".join(hex_groups)
        ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}   {hex_str:<50}   {ascii_repr}")
    return "\n".join(lines)


def format_hex_continuous(data: bytes, wrap: int = 96) -> str:
    if not data:
        return ""
    hx = data.hex()
    if wrap <= 0:
        return hx
    return "\n".join(hx[i : i + wrap] for i in range(0, len(hx), wrap))


# ============================================================================
# experiment_txt
# ============================================================================


def build_experiment_txt_report(
    *,
    version: str,
    domain: str,
    dns_server: str,
    qtype_name: str,
    iface: str,
    transaction_id: int,
    rtt_ms: float | None,
    got_response: bool,
    timed_out: bool,
    eth_frame: bytes,
    resp_frame: bytes | None,
    records: list[dict],
    pcap_path: str,
) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = [
        "=" * 76,
        "my_nslookup 实验报告 — 协议分析（原始帧十六进制）",
        "=" * 76,
        f"生成时间 : {ts}",
        f"工具版本 : {version}",
        "",
        "-" * 76,
        "一、查询参数",
        "-" * 76,
        f"  域名 / 查询名     : {domain}",
        f"  DNS 服务器       : {dns_server}",
        f"  记录类型         : {qtype_name}",
        f"  网卡             : {iface}",
        f"  Transaction ID   : 0x{transaction_id:04X}",
        f"  会话状态         : {'已收到应答' if got_response else ('超时' if timed_out else '失败')}",
    ]
    if rtt_ms is not None:
        label = "等待耗时" if timed_out else "往返时延 (RTT)"
        lines.append(f"  {label}       : {rtt_ms:.3f} ms")
    lines.append(f"  pcap 路径        : {pcap_path}")
    lines.extend(["", "-" * 76, "二、DNS 资源记录（逐条完整字段）", "-" * 76])
    if records:
        for i, r in enumerate(records, 1):
            lines.append(_format_rr_record_block(r, i, show_section=True))
            lines.append("")
    else:
        lines.append("  （无解析记录）")
    lines.extend(
        [
            "",
            "-" * 76,
            "三、请求侧 — 完整以太网帧（拼接：以太网头 + IP + UDP + DNS）",
            "-" * 76,
            f"  长度: {len(eth_frame)} 字节",
            "",
            format_hex_dump(eth_frame),
            "",
            "  --- 连续十六进制（无空格，每行 96 字符）---",
            format_hex_continuous(eth_frame, wrap=96) or "（空）",
        ]
    )
    lines.extend(
        [
            "",
            "-" * 76,
            "四、应答侧 — 完整以太网帧（若已捕获）",
            "-" * 76,
        ]
    )
    if resp_frame:
        lines.extend(
            [
                f"  长度: {len(resp_frame)} 字节",
                "",
                format_hex_dump(resp_frame),
                "",
                "  --- 连续十六进制（无空格，每行 96 字符）---",
                format_hex_continuous(resp_frame, wrap=96),
            ]
        )
    else:
        lines.append("  （本次未收到应答帧或超时）")
    lines.extend(["", "=" * 76, "报告结束", "=" * 76, ""])
    return "\n".join(lines)


def write_experiment_txt(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


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

APP_VERSION = "1.1.0"

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


def make_console(
    *, no_color: bool = False, soft_wrap: bool = True, record: bool = False
) -> Console:
    return Console(
        soft_wrap=soft_wrap, no_color=no_color, highlight=False, record=record
    )


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


def print_environment_check(
    console: Console,
    *,
    rows: list[tuple[str, str, str]],
) -> None:
    t = Table(
        title="运行前检查",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold blue",
        title_style="bold blue",
    )
    t.add_column("检查项", style="dim", no_wrap=True)
    t.add_column("结果", no_wrap=True)
    t.add_column("说明", style="white")
    for name, status, detail in rows:
        t.add_row(name, status, detail)
    console.print(Panel(t, border_style="blue"))
    console.print()


def print_executive_summary(
    console: Console,
    *,
    success: bool,
    timed_out: bool,
    rtt_ms: float | None,
    transaction_id: int,
    record_count: int,
    summ: dict[str, Any],
    pcap_path: str,
) -> None:
    border = "green" if success and not timed_out else "yellow"
    inner = Table(
        box=box.SIMPLE,
        show_header=False,
        padding=(0, 1),
    )
    inner.add_column("项", style="dim", width=18)
    inner.add_column("值", style="white")

    if timed_out:
        inner.add_row("状态", "[yellow]超时，未收到匹配应答[/yellow]")
    elif success:
        inner.add_row("状态", "[green]已收到 DNS 应答并完成解析[/green]")
    else:
        inner.add_row("状态", "[red]未完成[/red]")

    inner.add_row("Transaction ID", f"0x{transaction_id:04X}")
    if rtt_ms is not None:
        label = "等待耗时" if timed_out else "往返时延 (RTT)"
        inner.add_row(label, f"{rtt_ms:.2f} ms")
    inner.add_row("资源记录条数", str(record_count))
    inner.add_row("pcap 文件", pcap_path)

    v4 = summ.get("ipv4_addresses") or []
    v6 = summ.get("ipv6_addresses") or []
    cname = summ.get("cname_hops") or []
    if v4:
        inner.add_row("IPv4 解析", ", ".join(v4))
    if v6:
        inner.add_row("IPv6 解析", ", ".join(v6))
    if cname:
        inner.add_row("CNAME 链", "; ".join(cname))

    console.print(
        Panel(
            inner,
            title="查询结果摘要",
            title_align="left",
            border_style=border,
            box=box.ROUNDED,
        )
    )
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


def print_wire_hex_appendix(
    console: Console,
    *,
    eth_frame: bytes,
    resp_frame: bytes | None,
) -> None:
    console.print()
    console.print(
        Rule(
            "③ 线路上完整帧 — 十六进制转储（以太网帧整体字节）",
            style="dim",
        )
    )
    console.print()
    body_req = format_hex_dump(eth_frame)
    console.print(
        f"[bold]请求：完整以太网帧（链路层 → 应用层拼接）[/bold]  "
        f"[dim]({len(eth_frame)} 字节)[/dim]"
    )
    console.print()
    console.print(body_req, markup=False)
    console.print()
    if resp_frame:
        body_resp = format_hex_dump(resp_frame)
        console.print(
            f"[bold]应答：完整以太网帧[/bold]  "
            f"[dim]({len(resp_frame)} 字节)[/dim]"
        )
        console.print()
        console.print(body_resp, markup=False)
    else:
        console.print(
            Panel(
                "[dim]本次未捕获应答帧（超时或无匹配响应）[/dim]",
                title="应答",
                border_style="dim",
            )
        )
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
        "rtype": rtype,
        "value": value,
        "ttl": ttl,
        "rr_class": rclass,
        "rr_class_name": "IN" if rclass == 1 else str(rclass),
        "rdlength": rdlength,
    }
    return rec, offset


def _format_rr_record_block(
    rec: dict, index: int, *, show_section: bool = False
) -> str:
    rnum = rec.get("rtype")
    type_line = (
        f"{rec['type']} ({rnum})" if rnum is not None else str(rec["type"])
    )
    lines = [f"Record {index}:"]
    if show_section and rec.get("section"):
        lines.append(f"  Section  : {rec['section']}")
    lines.extend(
        [
            f"  Name     : {rec['name']}",
            f"  Type     : {type_line}",
            f"  Class    : {rec.get('rr_class_name', '—')} ({rec.get('rr_class', '')})",
            f"  TTL      : {rec['ttl']}",
            f"  RDLength : {rec.get('rdlength', '—')}",
            f"  RDATA    : {rec['value']}",
        ]
    )
    return "\n".join(lines)


def parse_dns_response(
    data: bytes,
    *,
    console: Console | None = None,
    layers: set[str] | None = None,
    merge_rr_sections: bool = True,
) -> list[dict]:
    """
    解析 DNS 应答；在 layer 包含 resp_dns 或 all 时用 Rich 打印。
    merge_rr_sections=True 时合并 Answer/Authority/Additional，逐条竖向打印完整字段（不截断）。
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
            blocks = [
                _format_rr_record_block(rec, i, show_section=True)
                for i, rec in enumerate(merged_rows, 1)
            ]
            body = "\n\n".join(blocks)
            console.print()
            console.print(
                Rule(
                    "DNS 资源记录（RR）全部信息 — 逐条完整字段",
                    style="bold cyan",
                )
            )
            console.print()
            console.print(body, markup=False)
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
            blocks = [
                _format_rr_record_block(rec, i, show_section=False)
                for i, rec in enumerate(section_recs, 1)
            ]
            body = "\n\n".join(blocks)
            console.print()
            console.print(Rule(title, style="bold cyan"))
            console.print()
            console.print(body, markup=False)
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
) -> tuple[object | None, float | None]:
    """
    先占住 UDP 源端口，避免内核因“无监听端口”向 DNS 回 ICMP Port Unreachable；
    在线程中 sniff，主线程 sendp 发以太帧；按 Transaction ID 匹配应答。
    返回 (应答报文或 None, 往返时延毫秒或 None)。
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
            f"已写入 [bold cyan]{len(scapy_pkts)}[/bold cyan] 个数据包\n"
            f"[dim]{escape(filename)}[/dim]",
            title="pcap",
            border_style="dim",
        )
    )

# ============================================================================
# main
# ============================================================================



def _interactive_prompts(defaults: dict) -> dict:
    from rich.prompt import Confirm, Prompt

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

    def _opt_str(label: str, key: str) -> str | None:
        d = defaults.get(key) or ""
        s = Prompt.ask(
            f"{label}（回车=自动）",
            default=str(d) if d else "",
            console=c,
        ).strip()
        return s if s else None

    src_mac = _opt_str("本机 MAC 地址", "src_mac")
    gw_mac = _opt_str("网关/下一跳 MAC", "gw_mac")
    src_ip = _opt_str("本机 IPv4 地址", "src_ip")

    sp_def = (
        str(defaults["src_port"])
        if defaults.get("src_port") is not None
        else ""
    )
    sp_in = Prompt.ask(
        "UDP 源端口（回车=随机端口）",
        default=sp_def,
        console=c,
    ).strip()
    src_port: int | None
    if not sp_in:
        src_port = None
    else:
        try:
            src_port = int(sp_in, 10)
            if not (1 <= src_port <= 65535):
                raise ValueError
        except ValueError:
            c.print("[red]UDP 源端口须为 1–65535 的整数[/red]")
            raise SystemExit(2) from None

    save_session = Confirm.ask(
        "是否将控制台全文保存为 txt？（等同 --session-log，含帧 hex 附录）",
        default=bool(defaults.get("session_log")),
        console=c,
    )
    session_log: str | None
    if save_session:
        sess_def = defaults.get("session_log") or "console_session.txt"
        sess_in = Prompt.ask("会话 txt 保存路径", default=sess_def, console=c).strip()
        session_log = sess_in or sess_def
    else:
        session_log = None

    save_exp_txt = Confirm.ask(
        "是否生成结构化文本实验报告？（等同 --export-txt）",
        default=bool(defaults.get("export_txt")),
        console=c,
    )
    export_txt: str | None
    if save_exp_txt:
        exp_def = defaults.get("export_txt") or "lab_report.txt"
        exp_in = Prompt.ask("实验报告 txt 路径", default=exp_def, console=c).strip()
        export_txt = exp_in or exp_def
    else:
        export_txt = None

    return {
        "dns_server": dns.strip(),
        "domain": domain,
        "qtype": qtype,
        "iface": iface.strip(),
        "show": show.strip(),
        "output": out.strip(),
        "order": order.strip().lower(),
        "src_mac": src_mac,
        "gw_mac": gw_mac,
        "src_ip": src_ip,
        "src_port": src_port,
        "session_log": session_log,
        "export_txt": export_txt,
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
    preflight: bool = False,
    no_summary: bool = False,
    export_report: str | None = None,
    json_output: str | None = None,
    emit_json_stdout: bool = False,
    timeout_sec: float = 5.0,
    show_hex: bool = False,
    export_txt: str | None = None,
    session_log_path: str | None = None,
) -> None:
    qtype_map = {"A": 1, "AAAA": 28, "CNAME": 5, "NS": 2, "MX": 15, "TXT": 16}
    qtype = qtype_map[qtype_name]

    src_port = (
        src_port
        if src_port is not None
        else random.randint(32768, 65535)
    )
    gw_ip = get_default_gateway()
    gw_mac = gw_mac or (get_gateway_mac(gw_ip) if gw_ip else None)

    print_title(console, f"v{APP_VERSION} · 链路层 DNS 查询与解析")

    if preflight:
        ok_iface = iface_exists(iface)
        ip_detail = "—"
        ip_ok = False
        if ok_iface:
            try:
                ip_detail = get_local_ip(iface)
                ip_ok = True
            except OSError as e:
                ip_detail = str(e)
        rows = [
            (
                "网卡设备",
                "[green]通过[/green]" if ok_iface else "[red]未通过[/red]",
                iface if ok_iface else f"未找到接口 {iface}",
            ),
            (
                "IPv4 地址",
                "[green]通过[/green]" if ip_ok else "[red]未通过[/red]",
                ip_detail,
            ),
            (
                "默认网关",
                "[green]已配置[/green]" if gw_ip else "[yellow]未配置[/yellow]",
                gw_ip or "—",
            ),
            (
                "下一跳 MAC",
                "[green]已解析[/green]" if gw_mac else "[red]未解析[/red]",
                gw_mac or "将阻塞发送，请检查网络或 --gw-mac",
            ),
            ("DNS 服务器", "—", dns_server),
        ]
        print_environment_check(console, rows=rows)

    src_ip = src_ip or get_local_ip(iface)
    src_mac = src_mac or get_local_mac(iface)

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

    response, rtt_ms = send_and_receive(
        eth_frame,
        iface,
        src_port,
        txid,
        timeout=timeout_sec,
        console=console,
        layers=layers,
    )

    out_path = output
    if not os.path.isabs(out_path):
        out_path = os.path.join(os.getcwd(), out_path)

    pcap_list: list[bytes] = [eth_frame]
    records: list[dict] = []
    got_response = response is not None
    resp_frame_bytes: bytes | None = None
    if response:
        resp_frame_bytes = raw(response)
        resp_raw = resp_frame_bytes
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
            records = parse_dns_response(
                dns_data, console=console, layers=layers, merge_rr_sections=True
            )
        else:
            records = parse_dns_response(
                dns_data, console=console, layers=layers, merge_rr_sections=True
            )
            if any_response_layer(layers):
                print_response_frame_layers(
                    console, resp_raw, layers, order="reverse"
                )
    else:
        print_timeout(console)

    save_pcap(pcap_list, out_path, console=console)

    if show_hex:
        print_wire_hex_appendix(
            console,
            eth_frame=eth_frame,
            resp_frame=resp_frame_bytes,
        )

    summ = summarize_dns_records(records)
    if not no_summary:
        print_executive_summary(
            console,
            success=got_response,
            timed_out=not got_response,
            rtt_ms=rtt_ms,
            transaction_id=txid,
            record_count=len(records),
            summ=summ,
            pcap_path=out_path,
        )

    payload = build_json_payload(
        version=APP_VERSION,
        success=got_response,
        domain=domain,
        dns_server=dns_server,
        qtype_name=qtype_name,
        iface=iface,
        transaction_id=txid,
        rtt_ms=rtt_ms,
        records=records,
        pcap_path=out_path,
        timeout=not got_response,
    )
    if export_report:
        md = render_markdown_report(payload)
        rp = export_report
        if not os.path.isabs(rp):
            rp = os.path.join(os.getcwd(), rp)
        write_text_report(rp, md)
        console.print(f"[dim]已写入 Markdown 报告:[/dim] [bold]{rp}[/bold]")
        console.print()
    if json_output:
        jp = json_output
        if not os.path.isabs(jp):
            jp = os.path.join(os.getcwd(), jp)
        with open(jp, "w", encoding="utf-8") as jf:
            json.dump(payload, jf, ensure_ascii=False, indent=2)
        console.print(f"[dim]已写入 JSON:[/dim] [bold]{jp}[/bold]")
        console.print()
    if emit_json_stdout:
        print(json.dumps(payload, ensure_ascii=False), flush=True)

    if export_txt:
        txt_body = build_experiment_txt_report(
            version=APP_VERSION,
            domain=domain,
            dns_server=dns_server,
            qtype_name=qtype_name,
            iface=iface,
            transaction_id=txid,
            rtt_ms=rtt_ms,
            got_response=got_response,
            timed_out=not got_response,
            eth_frame=eth_frame,
            resp_frame=resp_frame_bytes,
            records=records,
            pcap_path=out_path,
        )
        tp = export_txt
        if not os.path.isabs(tp):
            tp = os.path.join(os.getcwd(), tp)
        write_experiment_txt(tp, txt_body)
        console.print(f"[dim]已写入文本实验报告:[/dim] [bold]{tp}[/bold]")
        console.print()

    if session_log_path:
        lp = session_log_path
        if not os.path.isabs(lp):
            lp = os.path.join(os.getcwd(), lp)
        d = os.path.dirname(lp)
        if d:
            os.makedirs(d, exist_ok=True)
        text = console.export_text(clear=False, styles=False)
        with open(lp, "w", encoding="utf-8") as f:
            f.write(text)
        console.print(
            f"[dim]已写入会话全文（控制台输出副本）:[/dim] [bold]{escape(lp)}[/bold]"
        )
        console.print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="my_nslookup — 自定义 DNS 解析（链路层注入 + 抓包 + pcap）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 my_nslookup.py 8.8.8.8 www.baidu.com
  python3 my_nslookup.py 8.8.8.8 www.baidu.com --preflight
  python3 my_nslookup.py 8.8.8.8 www.baidu.com --export-report report.md --json-out session.json
  python3 my_nslookup.py 8.8.8.8 www.baidu.com --hex --export-txt lab_dump.txt
  python3 my_nslookup.py 8.8.8.8 example.com --session-log console.txt
  python3 my_nslookup.py 8.8.8.8 https://www.qq.com/ --show eth,ip,dns
  python3 my_nslookup.py -i
  python3 my_nslookup.py 114.114.114.114 example.com -S resp --no-color
  python3 my_nslookup.py 8.8.8.8 example.com --order reverse --timeout 3
  python3 my_nslookup.py 8.8.8.8 example.com --src-ip 192.168.1.100 --src-port 54321 --gw-mac aa:bb:cc:dd:ee:ff

--show 分层见: python3 my_nslookup.py --show-help
        """.strip(),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"my_nslookup {APP_VERSION}",
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
        help="交互式输入 DNS、域名、记录类型、网卡、显示层、可选本机/网关 MAC/IP/UDP 端口及是否保存会话/实验报告 txt 等",
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
    parser.add_argument(
        "--src-mac",
        metavar="MAC",
        help="本机以太网 MAC，如 aa:bb:cc:dd:ee:ff（默认由指定网卡 ioctl 读取）",
    )
    parser.add_argument(
        "--gw-mac",
        metavar="MAC",
        help="下一跳/网关 MAC（默认对默认网关 IP 发 ARP 解析）",
    )
    parser.add_argument(
        "--src-ip",
        metavar="IPv4",
        help="本机 IPv4 源地址（默认取 --iface 对应网卡的地址）",
    )
    parser.add_argument(
        "--src-port",
        type=int,
        default=None,
        metavar="PORT",
        help="UDP 源端口 1–65535（默认随机高位端口）",
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
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="正式演示前打印运行前检查表（网卡、IPv4、网关、ARP）",
    )
    parser.add_argument(
        "--no-summary",
        action="store_true",
        help="不打印结尾「查询结果摘要」面板",
    )
    parser.add_argument(
        "--export-report",
        metavar="FILE.md",
        default=None,
        help="将本次会话导出为 Markdown 报告（便于实验报告 / 答辩材料）",
    )
    parser.add_argument(
        "--json-out",
        dest="json_output",
        metavar="FILE.json",
        default=None,
        help="将结构化 JSON 结果写入文件",
    )
    parser.add_argument(
        "--emit-json",
        action="store_true",
        help="在程序结束前向标准输出打印一行 JSON（便于脚本集成）",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        metavar="SEC",
        help="等待 DNS 应答的超时时间（秒），默认 5",
    )
    parser.add_argument(
        "--hex",
        action="store_true",
        help="在解析输出之后打印请求/应答完整以太网帧的十六进制转储",
    )
    parser.add_argument(
        "--export-txt",
        metavar="FILE.txt",
        default=None,
        help="生成纯文本实验报告（含参数、RR 摘要、请求/应答帧十六进制与连续 hex）",
    )
    parser.add_argument(
        "--session-log",
        metavar="FILE.txt",
        default=None,
        help="将本次运行控制台完整输出（纯文本）写入文件；启用时自动包含与 --hex 相同的帧十六进制附录",
    )
    args = parser.parse_args()

    console = make_console(
        no_color=args.no_color,
        record=bool(args.session_log) or args.interactive,
    )

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

    session_log_path: str | None = args.session_log
    export_txt_path: str | None = args.export_txt

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
                "src_mac": args.src_mac,
                "gw_mac": args.gw_mac,
                "src_ip": args.src_ip,
                "src_port": args.src_port,
                "session_log": args.session_log,
                "export_txt": args.export_txt,
            }
        )
        dns_server = filled["dns_server"]
        domain_in = filled["domain"]
        qtype = filled["qtype"]
        iface = filled["iface"]
        layers = normalize_show(filled["show"])
        output = filled["output"]
        order = filled.get("order", args.order)
        src_mac = filled["src_mac"]
        gw_mac = filled["gw_mac"]
        src_ip = filled["src_ip"]
        src_port = filled["src_port"]
        session_log_path = filled["session_log"]
        export_txt_path = filled["export_txt"]
    elif not dns_server or not domain_in:
        console.print(
            "[red]请提供:[/red] DNS 服务器 IP 与域名，或使用 [bold]-i[/bold] 进入交互模式。"
        )
        parser.print_help()
        raise SystemExit(2)
    else:
        src_mac = args.src_mac
        gw_mac = args.gw_mac
        src_ip = args.src_ip
        src_port = args.src_port

    domain = normalize_domain(domain_in)

    run_once(
        dns_server=dns_server.strip(),
        domain=domain,
        qtype_name=qtype,
        src_mac=src_mac,
        gw_mac=gw_mac,
        src_ip=src_ip,
        src_port=src_port,
        iface=iface,
        output=output,
        layers=layers,
        console=console,
        order=order,
        preflight=args.preflight,
        no_summary=args.no_summary,
        export_report=args.export_report,
        json_output=args.json_output,
        emit_json_stdout=args.emit_json,
        timeout_sec=args.timeout,
        show_hex=args.hex or bool(session_log_path),
        export_txt=export_txt_path,
        session_log_path=session_log_path,
    )


if __name__ == "__main__":
    main()
