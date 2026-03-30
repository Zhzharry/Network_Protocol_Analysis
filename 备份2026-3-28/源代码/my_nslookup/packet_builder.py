"""手工构造 DNS / UDP / IPv4 / 以太帧。"""
import random
import socket
import struct

# 标准递归查询：QR=0, RD=1
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


