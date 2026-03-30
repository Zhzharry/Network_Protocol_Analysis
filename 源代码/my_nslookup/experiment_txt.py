"""纯文本实验报告（含完整帧十六进制转储）。"""
from __future__ import annotations

from datetime import datetime, timezone

from dns_parser import _format_rr_record_block
from hexdump_fmt import format_hex_continuous, format_hex_dump


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
