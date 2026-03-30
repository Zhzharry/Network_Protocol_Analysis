"""DNS 应答解析（含 RFC1035 压缩指针）。"""
import socket
import struct

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from display import LAYER_RESP_DNS, dns_flags_kv_rows, layer_visible


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
    """逐条竖向排版，与老师演示图4一致，避免表格列宽截断。"""
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
