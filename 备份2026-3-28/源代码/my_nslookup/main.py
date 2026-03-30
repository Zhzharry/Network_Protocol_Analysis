#!/usr/bin/env python3
"""my_nslookup：手工构造以太网 + IP + UDP + DNS，L2 发包并解析应答、写 pcap。"""
from __future__ import annotations

import argparse
import os
import random
import struct
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from display import (
    any_request_layer,
    any_response_layer,
    make_console,
    normalize_domain,
    normalize_show,
    print_outgoing_request_stack,
    print_phase_rule,
    print_request_size,
    print_response_frame_layers,
    print_session_summary,
    print_timeout,
    print_title,
    show_help_layers,
)
from dns_parser import parse_dns_response
from packet_builder import (
    DNS_QUERY_FLAGS,
    build_dns_query,
    build_ethernet,
    build_ip,
    build_udp,
)
from packet_sender import send_and_receive
from pcap_writer import save_pcap
from scapy.all import raw
from utils import get_default_gateway, get_gateway_mac, get_local_ip, get_local_mac


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
  python3 main.py 8.8.8.8 www.baidu.com
  python3 main.py 8.8.8.8 https://www.qq.com/ --show eth,ip,dns
  python3 main.py -i
  python3 main.py 114.114.114.114 example.com -S resp --no-color
  python3 main.py 8.8.8.8 example.com --order reverse

--show 分层见: python3 main.py --show-help
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
