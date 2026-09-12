"""Packet framing, field readers/writers, and the packet bodies this client needs.

Wire format (both directions):

    [0]     signature (0xAA)
    [1..2]  length, big-endian, counting everything after these three bytes
    [3]     opcode
    [4]     sequence  (only present when the opcode is encrypted)
    [5..]   body      (encrypted, with an encryption-specific tail)

Multi-byte integers are big-endian. Strings are codepage 949 (the client's
Korean codepage) and are length-prefixed: one byte for a "string8", two for
the "data16" blobs used by the server table.
"""

from __future__ import annotations

import random
import zlib
from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from .crypto import client_encryption_type, crc16, server_encryption_type, EncryptionType

SIGNATURE: Final = 0xAA
ENCODING: Final = "cp949"
HEADER_LENGTH: Final = 3


class ClientOpCode(IntEnum):
    """Opcodes for packets the client sends."""

    VERSION = 0x00
    LOGIN = 0x03
    EXIT_REQUEST = 0x0B
    CLIENT_REDIRECTED = 0x10
    WORLD_LIST_REQUEST = 0x18
    HEARTBEAT_RESPONSE = 0x45
    SERVER_TABLE_REQUEST = 0x57
    HOMEPAGE_REQUEST = 0x68
    SYNCHRONIZE_TICKS_RESPONSE = 0x75


class ServerOpCode(IntEnum):
    """Opcodes for packets the server sends (only the ones this client acts on)."""

    CONNECTION_INFO = 0x00
    LOGIN_MESSAGE = 0x02
    REDIRECT = 0x03
    USER_ID = 0x05
    WORLD_LIST = 0x36
    HEARTBEAT = 0x3B
    SERVER_TABLE_RESPONSE = 0x56
    SYNCHRONIZE_TICKS = 0x68
    ACCEPT_CONNECTION = 0x7E


class LoginMessageType(IntEnum):
    CONFIRM = 0
    CLEAR_NAME_MESSAGE = 3
    CLEAR_PSWD_MESSAGE = 5
    CHARACTER_DOESNT_EXIST = 14
    WRONG_PASSWORD = 15


class ServerTableRequestType(IntEnum):
    SERVER_ID = 0
    REQUEST_TABLE = 1


class BaseClass(IntEnum):
    PEASANT = 0
    WARRIOR = 1
    ROGUE = 2
    WIZARD = 3
    PRIEST = 4
    MONK = 5


class SocialStatus(IntEnum):
    """The social status byte on each world-list entry (Chaos.DarkAges SocialStatus)."""

    AWAKE = 0
    DO_NOT_DISTURB = 1
    DAY_DREAMING = 2
    NEED_GROUP = 3
    GROUPED = 4
    LONE_HUNTER = 5
    GROUP_HUNTING = 6
    NEED_HELP = 7


#: Statuses that mean the player is idle / away from the keyboard. Everyone else is
#: treated as an active player. The client sets DayDreaming when idle; a player sets
#: LoneHunter when soloing and not looking to interact.
AFK_STATUSES: frozenset[int] = frozenset({SocialStatus.DAY_DREAMING, SocialStatus.LONE_HUNTER})


class Reader:
    """Sequential big-endian reader over a decrypted packet body."""

    __slots__ = ("_data", "_position")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._position = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._position

    def read_bytes(self, count: int) -> bytes:
        if self.remaining < count:
            raise ValueError(f"packet truncated: wanted {count} bytes, {self.remaining} left")

        chunk = self._data[self._position : self._position + count]
        self._position += count

        return chunk

    def read_byte(self) -> int:
        return self.read_bytes(1)[0]

    def read_bool(self) -> bool:
        return self.read_byte() != 0

    def read_uint16(self) -> int:
        return int.from_bytes(self.read_bytes(2), "big")

    def read_uint32(self) -> int:
        return int.from_bytes(self.read_bytes(4), "big")

    def read_string8(self) -> str:
        return self.read_bytes(self.read_byte()).decode(ENCODING, errors="replace")

    def read_data16(self) -> bytes:
        return self.read_bytes(self.read_uint16())


class Writer:
    """Sequential big-endian writer for a packet body."""

    __slots__ = ("_buffer",)

    def __init__(self) -> None:
        self._buffer = bytearray()

    def write_bytes(self, data: bytes) -> None:
        self._buffer += data

    def write_byte(self, value: int) -> None:
        self._buffer.append(value & 0xFF)

    def write_uint16(self, value: int) -> None:
        self._buffer += (value & 0xFFFF).to_bytes(2, "big")

    def write_uint32(self, value: int) -> None:
        self._buffer += (value & 0xFFFFFFFF).to_bytes(4, "big")

    def write_string8(self, value: str) -> None:
        encoded = value.encode(ENCODING)[:255]
        self.write_byte(len(encoded))
        self.write_bytes(encoded)

    def to_bytes(self) -> bytes:
        return bytes(self._buffer)


@dataclass(frozen=True, slots=True)
class Frame:
    """One packet as it came off the wire, still encrypted."""

    opcode: int
    sequence: int
    body: bytes


def parse_frames(buffer: bytearray) -> list[Frame]:
    """Pops every complete packet off the front of `buffer`, leaving any partial tail behind."""
    frames: list[Frame] = []

    while len(buffer) > HEADER_LENGTH:
        length = int.from_bytes(buffer[1:3], "big")
        total = length + HEADER_LENGTH

        if len(buffer) < total:
            break

        if buffer[0] != SIGNATURE:
            raise ValueError(f"bad packet signature 0x{buffer[0]:02X}; stream is desynchronized")

        opcode = buffer[3]
        encrypted = server_encryption_type(opcode) is not EncryptionType.NONE
        body_start = 5 if encrypted else 4

        frames.append(
            Frame(
                opcode=opcode,
                sequence=buffer[4] if encrypted else 0,
                body=bytes(buffer[body_start:total]),
            )
        )

        del buffer[:total]

    return frames


def build_frame(opcode: int, body: bytes, sequence: int) -> bytes:
    """Wraps an already-encrypted body in its header."""
    encrypted = client_encryption_type(opcode) is not EncryptionType.NONE
    length = len(body) + (2 if encrypted else 1)

    header = bytearray((SIGNATURE, (length >> 8) & 0xFF, length & 0xFF, opcode))

    if encrypted:
        header.append(sequence)

    return bytes(header) + body


# --- client packet bodies ---


def version_body(version: int) -> bytes:
    writer = Writer()
    writer.write_uint16(version)
    writer.write_bytes(b"LK\0")

    return writer.to_bytes()


def server_table_request_body(
    request_type: ServerTableRequestType,
    server_id: int | None = None,
) -> bytes:
    writer = Writer()
    writer.write_byte(request_type)

    if request_type is ServerTableRequestType.SERVER_ID:
        if server_id is None:
            raise ValueError("a server id is required when requesting a specific server")

        writer.write_byte(server_id)

    return writer.to_bytes()


def client_redirected_body(seed: int, key: str, name: str, redirect_id: int) -> bytes:
    writer = Writer()
    writer.write_byte(seed)
    writer.write_string8(key)
    writer.write_string8(name)
    writer.write_uint32(redirect_id)

    return writer.to_bytes()


def login_body(name: str, password: str, client_id1: int = 1, client_id2: int = 1) -> bytes:
    """Builds the login packet, including the obfuscated client-id block the server validates.

    The block is two random bytes followed by the client ids and a CRC of the first id,
    each XORed against a keystream derived from the second random byte. The server
    recomputes both CRCs and rejects the login if either fails.
    """
    writer = Writer()
    writer.write_string8(name)
    writer.write_string8(password)

    noise = random.randint(0, 255)
    salt = random.randint(0, 255)

    def keystream(offset: int, size: int) -> int:
        base = (salt + offset) & 0xFF

        return int.from_bytes(bytes((base + i) & 0xFF for i in range(size)), "little")

    block = bytearray(12)
    block[0] = noise
    block[1] = (salt ^ ((noise + 59) & 0xFF)) & 0xFF
    block[2:6] = ((client_id1 ^ keystream(138, 4)) & 0xFFFFFFFF).to_bytes(4, "big")
    block[6:8] = ((crc16(client_id1.to_bytes(4, "little")) ^ keystream(94, 2)) & 0xFFFF).to_bytes(2, "big")
    block[8:12] = ((client_id2 ^ keystream(115, 4)) & 0xFFFFFFFF).to_bytes(4, "big")

    writer.write_bytes(bytes(block))
    writer.write_uint16((crc16(bytes(block)) ^ keystream(165, 2)) & 0xFFFF)
    writer.write_byte(1)
    writer.write_byte(0)

    return writer.to_bytes()


def exit_request_body(is_request: bool) -> bytes:
    """Builds a logout packet. is_request=False tells the server to log the character out."""
    return bytes((1 if is_request else 0,))


def heartbeat_response_body(first: int, second: int) -> bytes:
    # the reply swaps the two values the server sent
    return bytes((second, first))


def synchronize_ticks_response_body(server_ticks: int, client_ticks: int) -> bytes:
    writer = Writer()
    writer.write_uint32(server_ticks)
    writer.write_uint32(client_ticks)

    return writer.to_bytes()


# --- server packet bodies ---


@dataclass(frozen=True, slots=True)
class ConnectionInfo:
    table_checksum: int
    seed: int
    key: str


def parse_connection_info(body: bytes) -> ConnectionInfo:
    reader = Reader(body)
    reader.read_byte()

    return ConnectionInfo(
        table_checksum=reader.read_uint32(),
        seed=reader.read_byte(),
        key=reader.read_string8(),
    )


@dataclass(frozen=True, slots=True)
class ServerEntry:
    id: int
    address: str
    port: int
    name: str
    description: str


def parse_server_table(body: bytes) -> list[ServerEntry]:
    """Parses the zlib-compressed server table from a ServerTableResponse."""
    reader = Reader(body)
    data = zlib.decompress(reader.read_data16())

    if not data:
        return []

    table = Reader(data)
    count = table.read_byte()
    servers: list[ServerEntry] = []

    for _ in range(count):
        if table.remaining < 7:
            break

        server_id = table.read_byte()
        address = ".".join(str(octet) for octet in table.read_bytes(4))
        port = table.read_uint16()

        # a null-terminated "{name};{description}" string
        raw = bytearray()

        while table.remaining and (byte := table.read_byte()):
            raw.append(byte)

        name, _, description = raw.decode(ENCODING, errors="replace").partition(";")

        servers.append(
            ServerEntry(
                id=server_id,
                address=address,
                port=port,
                name=name,
                description=description,
            )
        )

    return servers


@dataclass(frozen=True, slots=True)
class Redirect:
    address: str
    port: int
    seed: int
    key: str
    name: str
    id: int


def parse_redirect(body: bytes) -> Redirect:
    reader = Reader(body)
    address = ".".join(str(octet) for octet in reversed(reader.read_bytes(4)))
    port = reader.read_uint16()
    reader.read_byte()  # length of the remaining fields; redundant

    return Redirect(
        address=address,
        port=port,
        seed=reader.read_byte(),
        key=reader.read_string8(),
        name=reader.read_string8(),
        id=reader.read_uint32(),
    )


@dataclass(frozen=True, slots=True)
class LoginMessage:
    type: int
    message: str

    @property
    def is_confirm(self) -> bool:
        return self.type == LoginMessageType.CONFIRM


def parse_login_message(body: bytes) -> LoginMessage:
    reader = Reader(body)

    return LoginMessage(type=reader.read_byte(), message=reader.read_string8())


@dataclass(frozen=True, slots=True)
class WorldListMember:
    base_class: int
    is_guilded: bool
    color: int
    social_status: int
    title: str
    is_master: bool
    name: str

    @property
    def class_name(self) -> str:
        try:
            return BaseClass(self.base_class).name.lower()
        except ValueError:
            return "unknown"

    @property
    def is_afk(self) -> bool:
        """True when the player's social status marks them as idle / away."""
        return self.social_status in AFK_STATUSES


@dataclass(frozen=True, slots=True)
class WorldList:
    """The country list: a total, then one entry per online player."""

    member_count: int
    members: list[WorldListMember]


def parse_world_list(body: bytes) -> WorldList:
    reader = Reader(body)
    member_count = reader.read_uint16()
    entry_count = reader.read_uint16()
    members: list[WorldListMember] = []

    for _ in range(entry_count):
        class_byte = reader.read_byte()

        members.append(
            WorldListMember(
                base_class=class_byte & 7,
                is_guilded=(class_byte & 8) != 0,
                color=reader.read_byte(),
                social_status=reader.read_byte(),
                title=reader.read_string8(),
                is_master=reader.read_bool(),
                name=reader.read_string8(),
            )
        )

    return WorldList(member_count=member_count, members=members)


def parse_heartbeat(body: bytes) -> tuple[int, int]:
    reader = Reader(body)

    return reader.read_byte(), reader.read_byte()


def parse_synchronize_ticks(body: bytes) -> int:
    return Reader(body).read_uint32()
