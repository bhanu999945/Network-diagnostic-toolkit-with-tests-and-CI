import argparse
import os
import socket
import struct
import time

def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF

def build_packet(ident, seq):
    header = struct.pack("!BBHHH", 8, 0, 0, ident, seq)   # type 8 = echo request
    payload = b"netdiag-payload"
    chk = checksum(header + payload)
    return struct.pack("!BBHHH", 8, 0, chk, ident, seq) + payload

def parse_reply(data):
    ihl = (data[0] & 0x0F) * 4                     # IP header length
    icmp_type, _, _, pid, pseq = struct.unpack("!BBHHH", data[ihl:ihl + 8])
    if icmp_type == 11:                            # time exceeded: original packet is embedded
        inner = data[ihl + 8:]
        inner_ihl = (inner[0] & 0x0F) * 4
        _, _, _, pid, pseq = struct.unpack("!BBHHH", inner[inner_ihl:inner_ihl + 8])
    return icmp_type, pid, pseq

def ping_once(host, seq, ident, timeout=2.0, ttl=64):
    """Return (rtt_ms, responder_ip, icmp_type) or None on timeout."""
    dest = socket.gethostbyname(host)
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        s.settimeout(timeout)
        sent = time.time()
        s.sendto(build_packet(ident, seq), (dest, 0))
        deadline = sent + timeout
        while time.time() < deadline:
            try:
                data, addr = s.recvfrom(1024)
            except socket.timeout:
                return None
            icmp_type, pid, pseq = parse_reply(data)
            if icmp_type in (0, 11) and pid == ident and pseq == seq:
                return (time.time() - sent) * 1000, addr[0], icmp_type
    return None

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="ICMP ping")
    ap.add_argument("host")
    ap.add_argument("-c", "--count", type=int, default=4)
    a = ap.parse_args()
    ident = os.getpid() & 0xFFFF
    rtts = []
    for seq in range(1, a.count + 1):
        r = ping_once(a.host, seq, ident)
        if r:
            rtts.append(r[0])
            print(f"reply from {r[1]}: seq={seq} time={r[0]:.1f} ms")
        else:
            print(f"seq={seq} request timed out")
        time.sleep(1)
    loss = 100 * (a.count - len(rtts)) / a.count
    print(f"\n{a.count} sent, {len(rtts)} received, {loss:.0f}% loss")
    if rtts:
        print(f"min/avg/max = {min(rtts):.1f}/{sum(rtts)/len(rtts):.1f}/{max(rtts):.1f} ms")
