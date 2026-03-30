#!/usr/bin/env python3
"""my_nslookup：手工构造以太网 + IP + UDP + DNS，L2 发包并解析应答、写 pcap。"""
from __future__ import annotations

import argparse
import json
import os
import random
import struct
import sys

from rich.markup import escape

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from display import (
    APP_VERSION,
    any_request_layer,
    any_response_layer,
    make_console,
    normalize_domain,
    normalize_show,
    print_environment_check,
    print_executive_summary,
    print_outgoing_request_stack,
    print_phase_rule,
    print_request_size,
    print_response_frame_layers,
    print_session_summary,
    print_timeout,
    print_title,
    print_wire_hex_appendix,
    show_help_layers,
)
from experiment_txt import build_experiment_txt_report, write_experiment_txt
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
from session_report import (
    build_json_payload,
    render_markdown_report,
    summarize_dns_records,
    write_text_report,
)
from utils import (
    get_default_gateway,
    get_gateway_mac,
    get_local_ip,
    get_local_mac,
    iface_exists,
)


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
        console.print(
            f"[dim]已写入 Markdown 报告:[/dim] [bold]{rp}[/bold]"
        )
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
  python3 main.py 8.8.8.8 www.baidu.com
  python3 main.py 8.8.8.8 www.baidu.com --preflight
  python3 main.py 8.8.8.8 www.baidu.com --export-report report.md --json-out session.json
  python3 main.py 8.8.8.8 www.baidu.com --hex --export-txt lab_dump.txt
  python3 main.py 8.8.8.8 example.com --session-log console.txt
  python3 main.py 8.8.8.8 example.com --src-ip 192.168.1.100 --src-port 54321 --gw-mac aa:bb:cc:dd:ee:ff
  python3 main.py 8.8.8.8 https://www.qq.com/ --show eth,ip,dns
  python3 main.py -i
  python3 main.py 114.114.114.114 example.com -S resp --no-color
  python3 main.py 8.8.8.8 example.com --order reverse --timeout 3

--show 分层见: python3 main.py --show-help
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
