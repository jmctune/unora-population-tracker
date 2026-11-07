"""Headless Dark Ages client that logs in, reads the country list once, and logs off.

The connection walks the standard lifecycle - lobby handshake, server select,
login redirect, world entry - then requests the world list a single time. As soon
as it arrives the client sends a logout and disconnects; `fetch` returns the list.

Only the packets needed to reach the world and read the country list are handled;
everything else the server sends is decrypted and ignored.
"""

from __future__ import annotations

import asyncio
import logging
import random
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum, auto

from . import protocol as p
from .crypto import Crypto, EncryptionType, client_encryption_type
from .version_resolver import CLIENT_VERSION_FALLBACK

logger = logging.getLogger("population_tracker.client")

#: The real client derives its two client ids from a per-machine registry
#: fingerprint. We instead generate a fresh random pair each run - within the
#: same range the client uses when it first generates its own - so a login is
#: never tied to this machine's hardware.
_CLIENT_ID_MAX = 2**31 - 2


def _random_client_ids() -> tuple[int, int]:
    return random.randint(1, _CLIENT_ID_MAX), random.randint(1, _CLIENT_ID_MAX)


class State(Enum):
    LOBBY = auto()
    LOGIN = auto()
    WORLD = auto()


@dataclass(slots=True)
class Credentials:
    name: str
    password: str


@dataclass(slots=True)
class Config:
    host: str
    port: int
    credentials: Credentials
    client_version: int = CLIENT_VERSION_FALLBACK
    server_id: int | None = None
    timeout: float = 30.0
    #: how long to wait after world entry before requesting the list, so the
    #: server has finished placing the character on a map
    world_entry_delay: float = 1.0


class LoginError(RuntimeError):
    """The server rejected the login (bad credentials, character missing, etc.)."""


class DarkAgesClient:
    def __init__(self, config: Config) -> None:
        self._config = config

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._crypto = Crypto()
        self._sequence = 0
        self._state = State.LOBBY
        self._client_id1, self._client_id2 = _random_client_ids()

        # a redirect captured mid-session; the read loop reconnects to it
        self._pending_redirect: p.Redirect | None = None
        # resolved with the country list, or failed on login rejection / disconnect
        self._result: asyncio.Future[p.WorldList] | None = None
        self._request_task: asyncio.Task[None] | None = None
        self._requested = False

    async def fetch(self) -> p.WorldList:
        """Runs one full login, returns the country list, and logs off. Raises on failure."""
        self._reset_for_lobby()
        self._result = asyncio.get_running_loop().create_future()

        await self._open(self._config.host, self._config.port)
        read_task = asyncio.create_task(self._read_loop())

        try:
            return await asyncio.wait_for(self._result, self._config.timeout)
        finally:
            if self._request_task is not None:
                self._request_task.cancel()

            read_task.cancel()

            try:
                await read_task
            except asyncio.CancelledError:
                pass

            await self._logout()
            await self._close()

    async def _read_loop(self) -> None:
        buffer = bytearray()

        try:
            while True:
                assert self._reader is not None
                chunk = await self._reader.read(65536)

                if not chunk:
                    self._fail(ConnectionError("connection closed before the country list arrived"))
                    return

                buffer += chunk

                for frame in p.parse_frames(buffer):
                    await self._dispatch(frame)

                    # once we have the list, stop - don't follow the logout redirect
                    if self._result is not None and self._result.done():
                        return

                    # a redirect tears down this socket, so stop draining the old buffer
                    if self._pending_redirect is not None:
                        await self._follow_redirect()
                        buffer.clear()
                        break
        except (OSError, ValueError) as exc:
            self._fail(exc)

    def _fail(self, exc: BaseException) -> None:
        if self._result is not None and not self._result.done():
            self._result.set_exception(exc)

    # --- connection lifecycle ---

    def _reset_for_lobby(self) -> None:
        self._crypto = Crypto()
        self._sequence = 0
        self._state = State.LOBBY
        self._client_id1, self._client_id2 = _random_client_ids()
        self._pending_redirect = None
        self._requested = False

    async def _open(self, host: str, port: int) -> None:
        logger.info("connecting to %s:%d", host, port)
        self._reader, self._writer = await asyncio.open_connection(host, port)
        sock = self._writer.get_extra_info("socket")

        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    async def _close(self) -> None:
        writer = self._writer
        self._reader = self._writer = None

        if writer is None:
            return

        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass

    async def _logout(self) -> None:
        """Sends a graceful logout so the server removes the character from the world."""
        if self._writer is None or self._state is not State.WORLD:
            return

        self._send(p.ClientOpCode.EXIT_REQUEST, p.exit_request_body(is_request=False))

        try:
            await self._writer.drain()
        except OSError:
            pass

    async def _follow_redirect(self) -> None:
        redirect = self._pending_redirect
        assert redirect is not None
        self._pending_redirect = None

        await self._close()

        # lobby->login keys off "default" (empty seed); login->world keys off the character name
        key_salt_seed = "" if self._state is State.LOGIN else redirect.name
        self._crypto = Crypto(redirect.seed, redirect.key, key_salt_seed)
        self._sequence = 0

        await self._open(redirect.address, redirect.port)

        # servers expect ClientRedirected immediately, without waiting for AcceptConnection
        self._send(
            p.ClientOpCode.CLIENT_REDIRECTED,
            p.client_redirected_body(redirect.seed, redirect.key, redirect.name, redirect.id),
        )

        if self._state is State.LOGIN:
            self._send(p.ClientOpCode.HOMEPAGE_REQUEST, b"")
            self._login()

    # --- io ---

    def _send(self, opcode: int, body: bytes) -> None:
        writer = self._writer

        if writer is None:
            return

        sequence = 0

        if client_encryption_type(opcode) is not EncryptionType.NONE:
            sequence = self._sequence & 0xFF
            self._sequence += 1
            body = self._crypto.client_encrypt(body, opcode, sequence)

        writer.write(p.build_frame(opcode, body, sequence))

    def _decrypt(self, frame: p.Frame) -> bytes:
        return self._crypto.client_decrypt(frame.body, frame.opcode, frame.sequence)

    # --- packet dispatch ---

    async def _dispatch(self, frame: p.Frame) -> None:
        handler = _HANDLERS.get(frame.opcode)

        if handler is None:
            return

        await handler(self, frame)

    async def _handle_accept_connection(self, _: p.Frame) -> None:
        # only the lobby connection responds with a version; redirects already sent ClientRedirected
        if self._state is State.LOBBY:
            self._send(p.ClientOpCode.VERSION, p.version_body(self._config.client_version))

    async def _handle_connection_info(self, frame: p.Frame) -> None:
        info = p.parse_connection_info(self._decrypt(frame))
        # the lobby always keys off "default"
        self._crypto = Crypto(info.seed, info.key, None)

        if self._state is State.LOBBY:
            self._send(
                p.ClientOpCode.SERVER_TABLE_REQUEST,
                p.server_table_request_body(p.ServerTableRequestType.REQUEST_TABLE),
            )

    async def _handle_server_table(self, frame: p.Frame) -> None:
        servers = p.parse_server_table(self._decrypt(frame))
        server_id = self._select_server(servers)
        logger.info("server table: %s -> selecting id %d", [s.name for s in servers], server_id)

        self._send(
            p.ClientOpCode.SERVER_TABLE_REQUEST,
            p.server_table_request_body(p.ServerTableRequestType.SERVER_ID, server_id),
        )

    def _select_server(self, servers: list[p.ServerEntry]) -> int:
        if self._config.server_id is not None:
            return self._config.server_id

        if not servers:
            raise ValueError("server table was empty and no server_id was configured")

        return servers[0].id

    async def _handle_redirect(self, frame: p.Frame) -> None:
        redirect = p.parse_redirect(self._decrypt(frame))
        # lobby->login, then login->world
        self._state = State.LOGIN if self._state is State.LOBBY else State.WORLD
        self._pending_redirect = redirect
        logger.info("redirect -> %s:%d (entering %s)", redirect.address, redirect.port, self._state.name)

    async def _handle_login_message(self, frame: p.Frame) -> None:
        message = p.parse_login_message(self._decrypt(frame))

        if message.is_confirm:
            logger.debug("login confirmed")
        else:
            logger.warning("login rejected [%d]: %s", message.type, message.message)
            self._fail(LoginError(message.message or f"login message type {message.type}"))

    async def _handle_user_id(self, _: p.Frame) -> None:
        if self._state is State.WORLD and not self._requested:
            self._requested = True
            logger.info("entered world as %s", self._config.credentials.name)
            self._request_task = asyncio.create_task(self._request_world_list())

    async def _request_world_list(self) -> None:
        await asyncio.sleep(self._config.world_entry_delay)
        logger.info("requesting country list")
        self._send(p.ClientOpCode.WORLD_LIST_REQUEST, b"")

    async def _handle_heartbeat(self, frame: p.Frame) -> None:
        first, second = p.parse_heartbeat(self._decrypt(frame))
        self._send(p.ClientOpCode.HEARTBEAT_RESPONSE, p.heartbeat_response_body(first, second))

    async def _handle_synchronize_ticks(self, frame: p.Frame) -> None:
        ticks = p.parse_synchronize_ticks(self._decrypt(frame))
        client_ticks = int(asyncio.get_running_loop().time() * 1000) & 0xFFFFFFFF
        self._send(
            p.ClientOpCode.SYNCHRONIZE_TICKS_RESPONSE,
            p.synchronize_ticks_response_body(ticks, client_ticks),
        )

    async def _handle_world_list(self, frame: p.Frame) -> None:
        world_list = p.parse_world_list(self._decrypt(frame))
        logger.info("country list received: %d online", world_list.member_count)

        if self._result is not None and not self._result.done():
            self._result.set_result(world_list)

    def _login(self) -> None:
        credentials = self._config.credentials
        logger.info("logging in as %s", credentials.name)
        self._send(
            p.ClientOpCode.LOGIN,
            p.login_body(credentials.name, credentials.password, self._client_id1, self._client_id2),
        )


_Handler = Callable[[DarkAgesClient, p.Frame], Awaitable[None]]

_HANDLERS: dict[int, _Handler] = {
    p.ServerOpCode.ACCEPT_CONNECTION: DarkAgesClient._handle_accept_connection,
    p.ServerOpCode.CONNECTION_INFO: DarkAgesClient._handle_connection_info,
    p.ServerOpCode.SERVER_TABLE_RESPONSE: DarkAgesClient._handle_server_table,
    p.ServerOpCode.REDIRECT: DarkAgesClient._handle_redirect,
    p.ServerOpCode.LOGIN_MESSAGE: DarkAgesClient._handle_login_message,
    p.ServerOpCode.USER_ID: DarkAgesClient._handle_user_id,
    p.ServerOpCode.HEARTBEAT: DarkAgesClient._handle_heartbeat,
    p.ServerOpCode.SYNCHRONIZE_TICKS: DarkAgesClient._handle_synchronize_ticks,
    p.ServerOpCode.WORLD_LIST: DarkAgesClient._handle_world_list,
}
