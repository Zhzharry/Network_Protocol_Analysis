"""会话结构化摘要、Markdown / JSON 导出（便于答辩材料与自动化）。"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


def summarize_dns_records(records: list[dict]) -> dict[str, Any]:
    """从解析后的 RR 列表提取演示常用字段。"""
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
    """生成可附在实验报告或答辩材料中的 Markdown 片段。"""
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
