import argparse
import socket
from concurrent.futures import ThreadPoolExecutor

def check_port(host, port, timeout=1.0):
    """Return 'open', 'closed' or 'filtered'."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return "open"
        except ConnectionRefusedError:   # RST received
            return "closed"
        except OSError:                  # timeout / unreachable
            return "filtered"

def scan(host, start, end, timeout=1.0, workers=100):
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(lambda p: (p, check_port(host, p, timeout)),
                              range(start, end + 1)))
    return [p for p, state in results if state == "open"]

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="TCP port scanner")
    ap.add_argument("host")
    ap.add_argument("--start", type=int, default=1)
    ap.add_argument("--end", type=int, default=1024)
    ap.add_argument("--timeout", type=float, default=1.0)
    a = ap.parse_args()


    for port in scan(a.host, a.start, a.end, a.timeout):
        print(f"{port}/tcp open")
