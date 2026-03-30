"""原始字节转可读的十六进制文本（控制台与实验报告共用）。"""


def format_hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    """
    经典十六进制 + ASCII 右侧对照，每行 bytes_per_line 字节。
    """
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
    """
    无分隔的连续十六进制字符串，按 wrap 字符换行（便于复制、检索）。
    """
    if not data:
        return ""
    hx = data.hex()
    if wrap <= 0:
        return hx
    return "\n".join(hx[i : i + wrap] for i in range(0, len(hx), wrap))
