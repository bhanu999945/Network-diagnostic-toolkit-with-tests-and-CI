import argparse
import os
from netdiag.ping import ping_once

def traceroute(host, max_hops=30):
    ident = os.getpid() & 0xFFFF
    for ttl in range(1, max_hops + 1):
        r = ping_once(host, seq=ttl, ident=ident, timeout=2.0, ttl=ttl)
        if r is None:
            print(f"{ttl:2d}  *")
            continue
        rtt, ip, icmp_type = r
        print(f"{ttl:2d}  {ip}  {rtt:.1f} ms")
        if icmp_type == 0:       # echo reply: destination reached
            break

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Traceroute")
    ap.add_argument("host")
    ap.add_argument("--max-hops", type=int, default=30)
    a = ap.parse_args()
    traceroute(a.host, a.max_hops)
