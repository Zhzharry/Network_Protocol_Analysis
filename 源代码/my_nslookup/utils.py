"""网络接口与网关信息（Linux ioctl / ARP）。"""
import os
import fcntl
import socket
import struct


def iface_exists(iface: str) -> bool:
    """Linux: 是否存在该网络接口（用于运行前检查）。"""
    if not iface:
        return False
    return os.path.isdir(os.path.join("/sys/class/net", iface))


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
    from scapy.all import ARP, Ether, srp

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
