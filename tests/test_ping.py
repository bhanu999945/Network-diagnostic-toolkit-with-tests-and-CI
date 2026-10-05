import os
import pytest
from netdiag.ping import build_packet, checksum, ping_once

def test_packet_checksum_is_valid():
    assert checksum(build_packet(1234, 1)) == 0     # a correct packet sums to 0

def test_packet_is_echo_request():
    assert build_packet(1, 1)[0] == 8

@pytest.mark.skipif(os.geteuid() != 0, reason="raw sockets need root")
def test_ping_localhost():
    assert ping_once("127.0.0.1", seq=1, ident=4321) is not None
def test_checksum_detects_corruption():
    pkt = bytearray(build_packet(1234, 1))
    pkt[-1] ^= 0xFF                       # flip bits in the payload
    assert checksum(bytes(pkt)) != 0

def test_packet_carries_ident_and_sequence():
    import struct
    _, _, _, ident, seq = struct.unpack("!BBHHH", build_packet(777, 5)[:8])
    assert (ident, seq) == (777, 5)
