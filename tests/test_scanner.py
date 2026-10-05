import socket
from netdiag.scanner import check_port, scan

def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

def test_open_port():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    assert check_port("127.0.0.1", port) == "open"
    srv.close()

def test_closed_port():
    assert check_port("127.0.0.1", _free_port()) == "closed"

def test_scan_finds_only_open_port():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    assert scan("127.0.0.1", port, port) == [port]
    srv.close()
def test_filtered_on_unroutable_address():
    # 10.255.255.1 is usually unroutable, so the connection times out
    assert check_port("10.255.255.1", 80, timeout=0.5) in ("filtered", "closed")

def test_scan_range_with_no_open_ports():
    p = _free_port()
    assert scan("127.0.0.1", p, p) == []
