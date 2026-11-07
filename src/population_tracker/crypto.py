"""Dark Ages packet encryption, ported from Chaos.Cryptography.Crypto.

The protocol uses three encryption modes, selected per opcode:

    NONE   - the body is sent in the clear (handshake and redirect packets)
    NORMAL - XOR against the negotiated key, salted by seed and sequence
    MD5    - XOR against a key derived per-packet from two random values that
             are appended (obfuscated) to the packet's tail

Client->server and server->client packets are *not* symmetric: a client packet
carries an extra encrypted byte, a 4-byte MD5 signature, and a 3-byte tail,
while a server packet carries only the 3-byte tail.
"""

from __future__ import annotations

import hashlib
import random
from enum import IntEnum
from typing import Final

from .tables import CRC16_TABLE, SALT_TABLE

DEFAULT_KEY: Final = "UrkcnItnI"
DEFAULT_KEY_SALT_SEED: Final = "default"
KEY_LENGTH: Final = 9

#: Opcodes whose client->server body is sent unencrypted.
_CLIENT_NONE: Final = frozenset({0x00, 0x10, 0x48})

#: Opcodes whose client->server body uses the negotiated key rather than a per-packet one.
_CLIENT_NORMAL: Final = frozenset(
    {0x02, 0x03, 0x04, 0x0B, 0x26, 0x2D, 0x3A, 0x42, 0x43, 0x4B, 0x57, 0x62, 0x68, 0x71, 0x73, 0x7B}
)

#: Opcodes whose server->client body is sent unencrypted.
_SERVER_NONE: Final = frozenset({0x00, 0x03, 0x40, 0x7E})

#: Opcodes whose server->client body uses the negotiated key rather than a per-packet one.
_SERVER_NORMAL: Final = frozenset({0x01, 0x02, 0x0A, 0x56, 0x60, 0x62, 0x66, 0x6F})


class EncryptionType(IntEnum):
    NONE = 0
    NORMAL = 1
    MD5 = 2


def client_encryption_type(opcode: int) -> EncryptionType:
    """The encryption applied to a packet the client sends."""
    if opcode in _CLIENT_NONE:
        return EncryptionType.NONE

    if opcode in _CLIENT_NORMAL:
        return EncryptionType.NORMAL

    return EncryptionType.MD5


def server_encryption_type(opcode: int) -> EncryptionType:
    """The encryption applied to a packet the server sends."""
    if opcode in _SERVER_NONE:
        return EncryptionType.NONE

    if opcode in _SERVER_NORMAL:
        return EncryptionType.NORMAL

    return EncryptionType.MD5


def crc16(data: bytes) -> int:
    """CRC-16/CCITT-FALSE, as used by the login packet's integrity fields."""
    crc = 0

    for byte in data:
        crc = (byte ^ (crc << 8) ^ CRC16_TABLE[(crc >> 8) & 0xFF]) & 0xFFFF

    return crc


def _md5_hex(value: str) -> str:
    return hashlib.md5(value.encode("ascii")).hexdigest()


def generate_key_salts(seed: str) -> bytes:
    """Expands a seed string into the 1024-byte salt pool used to derive MD5-mode keys.

    The pool is md5(md5(seed)) followed by 31 rounds of appending md5 of everything
    accumulated so far, as hex text.
    """
    text = _md5_hex(_md5_hex(seed))

    for _ in range(31):
        text += _md5_hex(text)

    return text.encode("ascii")


class Crypto:
    """Encrypts and decrypts packet bodies for one connection.

    A connection's crypto is replaced whenever the server hands out new parameters:
    once on the lobby handshake (ConnectionInfo) and again on each redirect.
    """

    __slots__ = ("key", "seed", "_key_salts", "_salts")

    def __init__(
        self,
        seed: int = 0,
        key: str = DEFAULT_KEY,
        key_salt_seed: str | None = None,
    ) -> None:
        self.seed = seed
        self.key = key.encode("ascii")
        self._salts = SALT_TABLE[seed]
        self._key_salts = generate_key_salts(key_salt_seed or DEFAULT_KEY_SALT_SEED)

    def generate_key(self, a: int, b: int) -> bytes:
        """Derives a 9-byte key from the two values carried in an MD5-mode packet's tail."""
        salts = self._key_salts
        count = len(salts)

        return bytes(salts[(i * (9 * i + b * b) + a) % count] for i in range(KEY_LENGTH))

    def _transform(self, buffer: bytearray, length: int, key: bytes, sequence: int) -> None:
        """XOR pass shared by encryption and decryption - the cipher is its own inverse."""
        salts = self._salts
        key_length = len(self.key)
        sequence_salt = salts[sequence]

        for i in range(length):
            salt_index = (i // key_length) % 256
            buffer[i] ^= salts[salt_index] ^ key[i % len(key)]

            if salt_index != sequence:
                buffer[i] ^= sequence_salt

    def client_encrypt(self, body: bytes, opcode: int, sequence: int) -> bytes:
        """Encrypts the body of a packet being sent to the server."""
        encryption_type = client_encryption_type(opcode)

        if encryption_type is EncryptionType.NONE:
            return body

        a = random.randint(256, 65534)
        b = random.randint(100, 254)

        if encryption_type is EncryptionType.NORMAL:
            key = self.key
            buffer = bytearray(len(body) + 8)
            buffer[: len(body)] = body
            # the byte after the body is left zero and encrypted along with it
            position = len(body) + 1
        else:
            key = self.generate_key(a, b)
            buffer = bytearray(len(body) + 9)
            buffer[: len(body)] = body
            position = len(body) + 1
            buffer[position] = opcode
            position += 1

        self._transform(buffer, position, key, sequence)

        digest = hashlib.md5(bytes((opcode, sequence)) + bytes(buffer[:position])).digest()
        buffer[position] = digest[13]
        buffer[position + 1] = digest[3]
        buffer[position + 2] = digest[11]
        buffer[position + 3] = digest[7]
        buffer[position + 4] = (a % 256) ^ 0x70
        buffer[position + 5] = b ^ 0x23
        buffer[position + 6] = ((a >> 8) % 256) ^ 0x74

        return bytes(buffer)

    def client_decrypt(self, body: bytes, opcode: int, sequence: int) -> bytes:
        """Decrypts the body of a packet received from the server."""
        encryption_type = server_encryption_type(opcode)

        if encryption_type is EncryptionType.NONE:
            return body

        length = len(body) - 3

        if length < 0:
            raise ValueError(f"packet 0x{opcode:02X} is too short to be encrypted ({len(body)} bytes)")

        a = ((body[length + 2] << 8) | body[length]) ^ 0x6474
        b = body[length + 1] ^ 0x24

        key = self.key if encryption_type is EncryptionType.NORMAL else self.generate_key(a, b)

        buffer = bytearray(body[:length])
        self._transform(buffer, length, key, sequence)

        return bytes(buffer)

    # The server-side operations below are the mirror of the two above. The real
    # server performs them; this client only needs them for the in-process mock
    # server used in tests, but keeping the pair together keeps the cipher in one place.

    def server_encrypt(self, body: bytes, opcode: int, sequence: int) -> bytes:
        """Encrypts the body of a packet being sent from the server."""
        encryption_type = server_encryption_type(opcode)

        if encryption_type is EncryptionType.NONE:
            return body

        a = random.randint(256, 65534)
        b = random.randint(100, 254)
        key = self.key if encryption_type is EncryptionType.NORMAL else self.generate_key(a, b)

        buffer = bytearray(body)
        self._transform(buffer, len(buffer), key, sequence)

        buffer.append((a & 0xFF) ^ 0x74)
        buffer.append(b ^ 0x24)
        buffer.append(((a >> 8) & 0xFF) ^ 0x64)

        return bytes(buffer)

    def server_decrypt(self, body: bytes, opcode: int, sequence: int) -> bytes:
        """Decrypts the body of a packet received by the server from a client."""
        encryption_type = client_encryption_type(opcode)

        if encryption_type is EncryptionType.NONE:
            return body

        length = len(body) - 7
        a = ((body[length + 6] << 8) | body[length + 4]) ^ 0x7470
        b = body[length + 5] ^ 0x23

        if encryption_type is EncryptionType.NORMAL:
            length -= 1
            key = self.key
        else:
            length -= 2
            key = self.generate_key(a, b)

        if length < 0:
            raise ValueError(f"packet 0x{opcode:02X} is too short to be encrypted ({len(body)} bytes)")

        buffer = bytearray(body[:length])
        self._transform(buffer, length, key, sequence)

        return bytes(buffer)
