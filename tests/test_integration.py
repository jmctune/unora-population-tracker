"""End-to-end lifecycle test against an in-process mock Dark Ages server.

The mock speaks the real wire protocol (framing + the validated server-side
crypto), so this exercises the client's full state machine: lobby handshake,
server select, login redirect, world entry, a single country-list request, and a
clean logout afterward.
"""

from __future__ import annotations

import asyncio
import zlib

from population_tracker.client import Config, Credentials, DarkAgesClient
from population_tracker.crypto import (
    Crypto,
    EncryptionType,
    client_encryption_type,
    server_encryption_type,
)
from population_tracker import protocol as p
from population_tracker.storage import PopulationSample

CHARACTER = "Tester"
SEED = 3
KEY = "ABCDEFGHI"


def _read_client_frames(buffer: bytearray) -> list[tuple[int, int, bytes]]:
    """Pops complete client->server frames, returning (opcode, sequence, encrypted_body)."""
    frames: list[tuple[int, int, bytes]] = []

    while len(buffer) > p.HEADER_LENGTH:
        length = int.from_bytes(buffer[1:3], "big")
        total = length + p.HEADER_LENGTH

        if len(buffer) < total:
            break

        opcode = buffer[3]
        encrypted = client_encryption_type(opcode) is not EncryptionType.NONE
        start = 5 if encrypted else 4
        frames.append((opcode, buffer[4] if encrypted else 0, bytes(buffer[start:total])))
        del buffer[:total]

    return frames


class _Connection:
    """Wraps one client socket with the crypto state and send-sequence for that phase."""

    def __init__(self, writer: asyncio.StreamWriter, crypto: Crypto) -> None:
        self._writer = writer
        self._crypto = crypto
        self._sequence = 0

    def set_crypto(self, crypto: Crypto) -> None:
        self._crypto = crypto

    def decrypt(self, opcode: int, sequence: int, body: bytes) -> bytes:
        return self._crypto.server_decrypt(body, opcode, sequence)

    def send(self, opcode: int, body: bytes) -> None:
        sequence = 0

        if server_encryption_type(opcode) is not EncryptionType.NONE:
            sequence = self._sequence & 0xFF
            self._sequence += 1
            body = self._crypto.server_encrypt(body, opcode, sequence)

        length = len(body) + (2 if server_encryption_type(opcode) is not EncryptionType.NONE else 1)
        header = bytearray((p.SIGNATURE, (length >> 8) & 0xFF, length & 0xFF, opcode))

        if server_encryption_type(opcode) is not EncryptionType.NONE:
            header.append(sequence)

        self._writer.write(bytes(header) + body)


def _server_table(login_host: str, login_port: int) -> bytes:
    inner = bytearray()
    inner.append(1)  # one server
    inner.append(1)  # server id
    inner += bytes(int(o) for o in login_host.split("."))
    inner += login_port.to_bytes(2, "big")
    inner += "Unora;Test".encode("cp949") + b"\x00"
    inner.append(0)  # show-server-list flag
    compressed = zlib.compress(bytes(inner))

    return len(compressed).to_bytes(2, "big") + compressed


def _redirect_body(host: str, port: int, seed: int, key: str, name: str, redirect_id: int) -> bytes:
    writer = p.Writer()
    writer.write_bytes(bytes(reversed([int(o) for o in host.split(".")])))
    writer.write_uint16(port)
    writer.write_byte(len(key) + len(name.encode("cp949")) + 7)
    writer.write_byte(seed)
    writer.write_string8(key)
    writer.write_string8(name)
    writer.write_uint32(redirect_id)

    return writer.to_bytes()


def _world_list_body(members: list[tuple[p.BaseClass, str, int]]) -> bytes:
    writer = p.Writer()
    writer.write_uint16(len(members))
    writer.write_uint16(len(members))

    for base_class, name, social_status in members:
        writer.write_byte(int(base_class))
        writer.write_byte(255)  # color
        writer.write_byte(social_status)
        writer.write_string8("")
        writer.write_byte(0)  # is master
        writer.write_string8(name)

    return writer.to_bytes()


class MockServer:
    """Three listeners (lobby/login/world) that walk a client to a world-list response."""

    MEMBERS = [
        (p.BaseClass.WARRIOR, "Aragorn", int(p.SocialStatus.AWAKE)),
        (p.BaseClass.WIZARD, "Gandalf", int(p.SocialStatus.GROUPED)),
        (p.BaseClass.WARRIOR, "Boromir", int(p.SocialStatus.DAY_DREAMING)),  # afk
        (p.BaseClass.PRIEST, "Elrond", int(p.SocialStatus.LONE_HUNTER)),  # afk
        (p.BaseClass.PEASANT, CHARACTER, int(p.SocialStatus.AWAKE)),  # our own probe client
    ]

    def __init__(self) -> None:
        self.world_list_requests = 0
        self.logout_received = False
        self.logout_event = asyncio.Event()
        self._servers: list[asyncio.Server] = []
        self.lobby_port = 0
        self.login_port = 0
        self.world_port = 0

    async def start(self) -> None:
        lobby = await asyncio.start_server(self._handle_lobby, "127.0.0.1", 0)
        login = await asyncio.start_server(self._handle_login, "127.0.0.1", 0)
        world = await asyncio.start_server(self._handle_world, "127.0.0.1", 0)
        self._servers = [lobby, login, world]
        self.lobby_port = lobby.sockets[0].getsockname()[1]
        self.login_port = login.sockets[0].getsockname()[1]
        self.world_port = world.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        for server in self._servers:
            server.close()

        for server in self._servers:
            await server.wait_closed()

    async def _pump(self, reader, conn, handler) -> None:
        buffer = bytearray()

        while True:
            chunk = await reader.read(65536)

            if not chunk:
                return

            buffer += chunk

            for opcode, sequence, body in _read_client_frames(buffer):
                if await handler(conn, opcode, sequence, body):
                    return

    async def _handle_lobby(self, reader, writer) -> None:
        conn = _Connection(writer, Crypto())
        conn.send(p.ServerOpCode.ACCEPT_CONNECTION, b"\x1bCONNECTED SERVER\n")

        async def handle(conn, opcode, sequence, body) -> bool:
            if opcode == p.ClientOpCode.VERSION:
                # advertise our negotiated crypto, then switch to decrypt with it
                info = p.Writer()
                info.write_byte(0)
                info.write_uint32(0)
                info.write_byte(SEED)
                info.write_string8(KEY)
                conn.send(p.ServerOpCode.CONNECTION_INFO, info.to_bytes())
                conn.set_crypto(Crypto(SEED, KEY, None))
            elif opcode == p.ClientOpCode.SERVER_TABLE_REQUEST:
                request_type = conn.decrypt(opcode, sequence, body)[0]

                if request_type == p.ServerTableRequestType.REQUEST_TABLE:
                    conn.send(p.ServerOpCode.SERVER_TABLE_RESPONSE, _server_table("127.0.0.1", self.login_port))
                else:  # ServerId -> redirect to login
                    conn.send(
                        p.ServerOpCode.REDIRECT,
                        _redirect_body("127.0.0.1", self.login_port, SEED, KEY, "", 1000),
                    )
                    writer.close()
                    return True

            return False

        await self._pump(reader, conn, handle)

    async def _handle_login(self, reader, writer) -> None:
        conn = _Connection(writer, Crypto(SEED, KEY, ""))
        conn.send(p.ServerOpCode.ACCEPT_CONNECTION, b"\x1bCONNECTED SERVER\n")

        async def handle(conn, opcode, sequence, body) -> bool:
            if opcode == p.ClientOpCode.LOGIN:
                conn.send(p.ServerOpCode.LOGIN_MESSAGE, bytes([p.LoginMessageType.CONFIRM]) + b"\x00")
                conn.send(
                    p.ServerOpCode.REDIRECT,
                    _redirect_body("127.0.0.1", self.world_port, SEED, KEY, CHARACTER, 2000),
                )
                writer.close()
                return True

            return False

        await self._pump(reader, conn, handle)

    async def _handle_world(self, reader, writer) -> None:
        conn = _Connection(writer, Crypto(SEED, KEY, CHARACTER))

        async def handle(conn, opcode, sequence, body) -> bool:
            if opcode == p.ClientOpCode.CLIENT_REDIRECTED:
                # confirm world entry with a UserId packet
                user_id = p.Writer()
                user_id.write_uint32(12345)
                user_id.write_bytes(bytes(6))
                conn.send(p.ServerOpCode.USER_ID, user_id.to_bytes())
            elif opcode == p.ClientOpCode.WORLD_LIST_REQUEST:
                self.world_list_requests += 1
                conn.send(p.ServerOpCode.WORLD_LIST, _world_list_body(self.MEMBERS))
            elif opcode == p.ClientOpCode.EXIT_REQUEST:
                # is_request=false is a logout; the client should send exactly this
                self.logout_received = conn.decrypt(opcode, sequence, body)[0] == 0
                self.logout_event.set()
                writer.close()
                return True

            return False

        await self._pump(reader, conn, handle)


def test_full_lifecycle_logs_in_reads_list_and_logs_off():
    asyncio.run(_run_lifecycle())


async def _run_lifecycle():
    server = MockServer()
    await server.start()

    config = Config(
        host="127.0.0.1",
        port=server.lobby_port,
        credentials=Credentials(name=CHARACTER, password="secret"),
        server_id=1,
        timeout=15,
        world_entry_delay=0.1,
    )
    client = DarkAgesClient(config)

    try:
        world_list = await client.fetch()
        # the logout is sent as fetch() tears down; wait for the server to see it
        await asyncio.wait_for(server.logout_event.wait(), timeout=2)
    finally:
        await server.stop()

    assert world_list.member_count == 5
    assert [m.name for m in world_list.members] == ["Aragorn", "Gandalf", "Boromir", "Elrond", CHARACTER]
    # excluding our own probe character: 4 others remain, two of them afk
    # (daydreaming + lone hunter), so two are active
    sample = PopulationSample.from_world_list(world_list, exclude_name=CHARACTER)
    assert sample.total == 4
    assert sample.active == 2
    assert sample.class_counts["peasant"] == 0  # our probe peasant is not counted
    # exactly one request, and a clean logout afterward
    assert server.world_list_requests == 1
    assert server.logout_received
