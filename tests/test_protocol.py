"""Pure-Python protocol tests (no server or C# harness required)."""

from __future__ import annotations

import zlib

from population_tracker import protocol as p
from population_tracker.crypto import (
    Crypto,
    EncryptionType,
    client_encryption_type,
    crc16,
    server_encryption_type,
)


def _server_frame(opcode: int, body: bytes, sequence: int) -> bytes:
    """Builds a server->client wire frame (0xAA, len, opcode, [seq], body)."""
    encrypted = server_encryption_type(opcode) is not EncryptionType.NONE
    payload = bytes([opcode]) + (bytes([sequence]) if encrypted else b"") + body

    return bytes([p.SIGNATURE]) + len(payload).to_bytes(2, "big") + payload


def test_parse_frames_reads_encrypted_and_plain():
    # 0x00 (ConnectionInfo) is unencrypted server-side; 0x36 (WorldList) is encrypted
    for opcode, body, sequence in [(0x00, b"\x01\x02\x03", 0), (0x36, b"payload", 42)]:
        buffer = bytearray(_server_frame(opcode, body, sequence))
        frames = p.parse_frames(buffer)

        assert len(frames) == 1
        assert buffer == b""  # fully consumed
        assert frames[0].opcode == opcode
        assert frames[0].body == body

        if server_encryption_type(opcode) is not EncryptionType.NONE:
            assert frames[0].sequence == sequence


def test_parse_frames_reads_multiple_and_leaves_partial_tail():
    stream = _server_frame(0x00, b"abc", 0) + _server_frame(0x36, b"de", 5)
    fragment = _server_frame(0x00, b"xyz", 0)[:2]
    buffer = bytearray(stream + fragment)

    frames = p.parse_frames(buffer)

    assert [f.body for f in frames] == [b"abc", b"de"]
    assert bytes(buffer) == fragment  # the fragment is preserved for the next read


def test_crc16_matches_chaos_variant():
    # Chaos's Generate16 seeds the register with 0 (poly 0x1021); cross-checked against
    # the C# library via tools/validate_crypto.py. Empty input yields 0.
    assert crc16(b"") == 0
    assert crc16(b"123456789") == 0xBEEF


def test_reader_writer_round_trip():
    writer = p.Writer()
    writer.write_byte(0x7F)
    writer.write_uint16(0xBEEF)
    writer.write_uint32(0xDEADBEEF)
    writer.write_string8("hello")
    writer.write_bytes(b"\x00\x01")

    reader = p.Reader(writer.to_bytes())

    assert reader.read_byte() == 0x7F
    assert reader.read_uint16() == 0xBEEF
    assert reader.read_uint32() == 0xDEADBEEF
    assert reader.read_string8() == "hello"
    assert reader.read_bytes(2) == b"\x00\x01"


def test_parse_server_table():
    inner = bytearray()
    inner.append(2)  # server count
    inner += bytes([1, 127, 0, 0, 1])  # id + ip
    inner += (4200).to_bytes(2, "big")  # port
    inner += "Unora;A fun server".encode("cp949") + b"\x00"
    inner += bytes([2, 10, 0, 0, 5])
    inner += (2611).to_bytes(2, "big")
    inner += "Second".encode("cp949") + b"\x00"
    inner.append(1)  # show-server-list flag

    body = len(zlib.compress(bytes(inner))).to_bytes(2, "big") + zlib.compress(bytes(inner))
    servers = p.parse_server_table(body)

    assert [s.name for s in servers] == ["Unora", "Second"]
    assert servers[0].address == "127.0.0.1"
    assert servers[0].port == 4200
    assert servers[0].description == "A fun server"
    assert servers[1].port == 2611


def test_parse_world_list_round_trip():
    writer = p.Writer()
    writer.write_uint16(2)  # member count
    writer.write_uint16(2)  # entry count
    # entry 1: monk, guilded
    writer.write_byte(int(p.BaseClass.MONK) | 8)
    writer.write_byte(255)  # color
    writer.write_byte(0)  # social status
    writer.write_string8("Master")
    writer.write_byte(1)  # is master
    writer.write_string8("Alice")
    # entry 2: wizard, not guilded
    writer.write_byte(int(p.BaseClass.WIZARD))
    writer.write_byte(151)
    writer.write_byte(2)
    writer.write_string8("")
    writer.write_byte(0)
    writer.write_string8("Bob")

    world_list = p.parse_world_list(writer.to_bytes())

    assert world_list.member_count == 2
    assert [m.name for m in world_list.members] == ["Alice", "Bob"]
    assert world_list.members[0].class_name == "monk"
    assert world_list.members[0].is_guilded is True
    assert world_list.members[1].class_name == "wizard"
    assert world_list.members[1].is_guilded is False


def test_redirect_reverses_ip():
    writer = p.Writer()
    writer.write_bytes(bytes([1, 0, 0, 127]))  # ip, reversed on the wire
    writer.write_uint16(2610)
    writer.write_byte(0)  # trailing length byte, ignored
    writer.write_byte(5)  # seed
    writer.write_string8("thekey")
    writer.write_string8("Alice")
    writer.write_uint32(123456)

    redirect = p.parse_redirect(writer.to_bytes())

    assert redirect.address == "127.0.0.1"
    assert redirect.port == 2610
    assert redirect.seed == 5
    assert redirect.key == "thekey"
    assert redirect.name == "Alice"
    assert redirect.id == 123456


def test_login_body_is_self_consistent():
    # the two embedded CRCs must validate against each other (mirrors the server check)
    body = p.login_body("Alice", "hunter2", client_id1=1, client_id2=1)
    reader = p.Reader(body)

    assert reader.read_string8() == "Alice"
    assert reader.read_string8() == "hunter2"

    block = reader.read_bytes(12)
    checksum = reader.read_uint16()

    noise = block[0]
    salt_key = block[1] ^ ((noise + 59) & 0xFF)

    def keystream(offset: int, size: int) -> int:
        base = (salt_key + offset) & 0xFF
        return int.from_bytes(bytes((base + i) & 0xFF for i in range(size)), "little")

    client_id1 = int.from_bytes(block[2:6], "big") ^ keystream(138, 4)
    embedded_crc1 = int.from_bytes(block[6:8], "big") ^ keystream(94, 2)
    integrity = checksum ^ keystream(165, 2)

    assert client_id1 == 1
    assert embedded_crc1 == crc16(client_id1.to_bytes(4, "little"))
    assert integrity == crc16(block)


def test_login_block_validates_for_arbitrary_client_ids():
    # the integrity CRCs must hold for any client id, not just 1/1
    for client_id1, client_id2 in [(1, 1), (2**31 - 2, 12345), (987654321, 2**31 - 2)]:
        body = p.login_body("Zeta", "pw", client_id1=client_id1, client_id2=client_id2)
        reader = p.Reader(body)
        reader.read_string8()
        reader.read_string8()
        block = reader.read_bytes(12)
        checksum = reader.read_uint16()

        noise = block[0]
        salt_key = block[1] ^ ((noise + 59) & 0xFF)

        def keystream(offset: int, size: int, key: int = salt_key) -> int:
            base = (key + offset) & 0xFF
            return int.from_bytes(bytes((base + i) & 0xFF for i in range(size)), "little")

        recovered_id1 = int.from_bytes(block[2:6], "big") ^ keystream(138, 4)
        embedded_crc1 = int.from_bytes(block[6:8], "big") ^ keystream(94, 2)
        recovered_id2 = int.from_bytes(block[8:12], "big") ^ keystream(115, 4)
        integrity = checksum ^ keystream(165, 2)

        assert recovered_id1 == client_id1
        assert recovered_id2 == client_id2
        assert embedded_crc1 == crc16(client_id1.to_bytes(4, "little"))
        assert integrity == crc16(block)


def test_random_client_ids_vary_and_stay_in_range():
    from population_tracker.client import _CLIENT_ID_MAX, _random_client_ids

    pairs = {_random_client_ids() for _ in range(50)}

    assert len(pairs) > 1  # not a constant
    for id1, id2 in pairs:
        assert 1 <= id1 <= _CLIENT_ID_MAX
        assert 1 <= id2 <= _CLIENT_ID_MAX


def test_encryption_type_tables_match_protocol():
    assert client_encryption_type(0x00) is EncryptionType.NONE
    assert client_encryption_type(0x10) is EncryptionType.NONE
    assert client_encryption_type(0x03) is EncryptionType.NORMAL
    assert client_encryption_type(0x18) is EncryptionType.MD5


def test_crypto_transform_is_symmetric():
    # the XOR pass is its own inverse; decrypting then re-applying yields the original
    crypto = Crypto(3, "ABCDEFGHI", "somechar")
    buffer = bytearray(b"the quick brown fox jumps")
    original = bytes(buffer)
    key = crypto.generate_key(12345, 200)

    crypto._transform(buffer, len(buffer), key, sequence=7)
    assert bytes(buffer) != original
    crypto._transform(buffer, len(buffer), key, sequence=7)
    assert bytes(buffer) == original
