"""终端界面：Rich 表格/面板 + 显示层筛选。"""
from __future__ import annotations

import socket
import struct
from typing import Iterable

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

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
