import argparse
import asyncio
import logging
import os
from functools import cached_property
from ipaddress import ip_address, IPv4Address
from types import TracebackType
from typing import Callable, Self, Type


class CnfseServer:
    dest_host: str
    dest_port: int
    inject_host_header: bytes
    prepend_inject_host: bool
    override_host_header: bytes | None
    drop_x_headers: bool
    host: str
    port: int

    _server: asyncio.Server | None
    _conns: set['CnfseConnection']

    _logger: logging.Logger

    def __init__(self,
                 dest_host: str,
                 dest_port: int,
                 inject_host: str,
                 prepend_inject_host: bool = False,
                 override_host: str | None = None,
                 drop_x_headers: bool = False,
                 listen_host: str = '127.0.0.1',
                 listen_port: int = 8080,
                 logger: logging.Logger | None = None) -> None:
        self.dest_host = dest_host
        self.dest_port = dest_port
        self.inject_host_header = b'Host: ' + inject_host.encode('ascii')
        self.prepend_inject_host = prepend_inject_host
        self.override_host_header = b'Host: ' + override_host.encode('ascii') if override_host is not None else None
        self.drop_x_headers = drop_x_headers
        self.host = listen_host
        self.port = listen_port

        self._server = None
        self._conns = set()

        self._logger = logger if logger else logging.getLogger(self.__class__.__name__)

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._on_client_connect,
            host=self.host,
            port=self.port
        )
        await self._server.start_serving()

    async def serve_forever(self) -> None:
        if self._server is None:
            raise RuntimeError('Server not started')

        await self._server.serve_forever()

    async def close(self) -> None:
        if self._server is None:
            return

        self._server.close()

        self._logger.info('Closing all connections...')
        for conn in set(self._conns):
            await conn.close()

        self._logger.info('Shutting down server...')
        await self._server.wait_closed()

    @property
    def listen_addresses(self) -> list[str]:
        if self._server is None:
            raise RuntimeError('Server not started')

        addresses: list[str] = []
        for sock in self._server.sockets:
            addr, port = sock.getsockname()
            ip = ip_address(addr)
            if isinstance(ip, IPv4Address):
                addr_str = addr
            else:
                addr_str = f'[{addr}]'

            addresses.append(f'{addr_str}:{port}')

        return addresses

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self,
                        exc_type: Type[BaseException] | None,
                        exc: BaseException | None,
                        tb: TracebackType | None) -> None:
        await self.close()

    def _on_client_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conn = CnfseConnection(server=self,
                               reader=reader,
                               writer=writer,
                               logger=self._logger,
                               on_done_callback=self._conns.discard)
        self._conns.add(conn)
        self._logger.info(f'Received connection from {conn.peername}')


class CnfseConnection:
    server: CnfseServer

    _reader: asyncio.StreamReader
    _writer: asyncio.StreamWriter

    _task: asyncio.Task[None]
    _on_done_callback: Callable[[Self], None] | None

    _logger: logging.Logger

    def __init__(self,
                 server: CnfseServer,
                 reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter,
                 on_done_callback: Callable[[Self], None] | None = None,
                 logger: logging.Logger | None = None) -> None:
        self.server = server

        self._reader = reader
        self._writer = writer

        self._task = asyncio.create_task(self._process_conn())
        self._on_done_callback = on_done_callback

        self._logger = logger.getChild(self.peername) if logger else logging.getLogger(
            f'{self.__class__.__name__}.{self.peername}')

    @cached_property
    def peername(self) -> str:
        pn = self._writer.get_extra_info('peername', None)

        addr, port = pn
        ip = ip_address(addr)
        if isinstance(ip, IPv4Address):
            addr_str = addr
        else:
            addr_str = f'[{addr}]'
        return f'{addr_str}:{port}'

    async def close(self) -> None:
        if not self._task.done():
            self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self._logger.error('Exception while handling connection:', exc_info=e)

        await self._close_conn()

    async def _close_conn(self) -> None:
        if self._writer.can_write_eof():
            self._writer.write_eof()
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except Exception:
            pass

    async def _process_conn(self) -> None:
        try:
            # Parse HTTP start-line and headers
            try:
                request = await self._reader.readuntil(b'\r\n\r\n')
            except asyncio.IncompleteReadError:
                self._logger.error('Incomplete HTTP request read')
                return
            message_fields = request.split(b'\r\n')
            if len(message_fields) < 3:
                self._logger.error('Invalid HTTP message')
                return
            startline = message_fields[0]
            try:
                _, _, version = startline.split(maxsplit=3)
            except ValueError:
                self._logger.warning('Invalid HTTP start-line')
                return
            if version not in {b'HTTP/1.0', b'HTTP/1.1'}:
                self._logger.warning('Unsupported HTTP version')
                return

            # Parse existing headers and drop them if necessary
            connection_header_exists = False
            headers: list[bytes] = []
            for hdr in message_fields[1:-2]:
                lower = hdr.lower()
                if self.server.override_host_header and lower.startswith(b'host:'):
                    continue
                if self.server.drop_x_headers and lower.startswith(b'x-'):
                    continue
                if not connection_header_exists and lower.startswith(b'connection:'):
                    _, value = lower.split(b':', maxsplit=1)
                    value = value.strip()
                    # We don't handle persistent keepalives
                    if value != b'upgrade' and value != b'close':
                        self._logger.warning(f'HTTP connection "{value.decode("ascii")}" not supported')
                        connection_header_exists = False
                        continue
                    else:
                        connection_header_exists = True
                headers.append(hdr)
            if self.server.override_host_header:
                headers.append(self.server.override_host_header)
            if not connection_header_exists:
                headers.append(b'Connection: close')

            # Inject duplicate header
            if self.server.prepend_inject_host:
                headers.insert(0, self.server.inject_host_header)
            else:
                headers.append(self.server.inject_host_header)

            # Connect to actual destination
            try:
                dest_reader, dest_writer = await asyncio.open_connection(host=self.server.dest_host,
                                                                         port=self.server.dest_port)
            except ConnectionError as e:
                self._logger.error(f'Failed to connect to destination: {e}')
                return
            try:
                # Send mangled request
                dest_writer.write(startline)
                dest_writer.write(b'\r\n')
                for hdr in headers:
                    dest_writer.write(hdr)
                    dest_writer.write(b'\r\n')
                dest_writer.write(b'\r\n')
                await dest_writer.drain()

                # Proxy request body
                await self._proxy_to(dest_reader, dest_writer)
                self._logger.info('Disconnected')
            except ConnectionError as e:
                self._logger.error(f'Connection error during proxy: {e}')
            finally:
                if dest_writer.can_write_eof():
                    dest_writer.write_eof()
                dest_writer.close()
                try:
                    await dest_writer.wait_closed()
                except Exception:
                    pass
        except Exception as e:
            self._logger.warning(f'Unhandled exception while handling request:', exc_info=e)
        finally:
            await self._close_conn()
            if self._on_done_callback is not None:
                self._on_done_callback(self)

    async def _proxy_to(self,
                        r: asyncio.StreamReader,
                        w: asyncio.StreamWriter,
                        chunk_size: int = 65536) -> None:
        p1 = asyncio.create_task(self._pipe(r, self._writer, chunk_size))
        p2 = asyncio.create_task(self._pipe(self._reader, w, chunk_size))

        done, pending = await asyncio.wait((p1, p2), return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()

        await asyncio.gather(*done, *pending, return_exceptions=True)
        for t in done:
            if not t.cancelled() and (exc := t.exception()):
                raise exc

    @staticmethod
    async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, chunk_size: int):
        while True:
            data = await reader.read(chunk_size)
            if not data:
                break
            writer.write(data)
            await writer.drain()


async def main(args: argparse.Namespace) -> None:
    server = CnfseServer(
        dest_host=args.dest_host,
        dest_port=args.dest_port,
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        inject_host=args.inject_host,
        override_host=args.override_host,
        prepend_inject_host=args.prepend_inject_host,
        drop_x_headers=args.drop_x_headers
    )
    async with server:
        logging.info(f'Server listening on {", ".join(server.listen_addresses)}')
        try:
            await server.serve_forever()
        except asyncio.CancelledError:
            pass

if __name__ == '__main__':
    argparser = argparse.ArgumentParser(description='HTTP virtual host confusion tool',
                                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    env_host = os.environ.get('CNFSE_DEST_HOST')
    env_inject_host = os.environ.get('CNFSE_INJECT_HOST')

    argparser.add_argument('-d', '--dest-host', type=str, required=not env_host,
                           default=env_host,
                           help='destination host')
    argparser.add_argument('-p', '--dest-port', type=int,
                           default=int(os.environ.get('CNFSE_DEST_PORT', '80')),
                           help='destination port')
    argparser.add_argument('-l', '--listen-host', type=str,
                           default=os.environ.get('CNFSE_LISTEN_HOST', '127.0.0.1'),
                           help='listen host')
    argparser.add_argument('-P', '--listen-port', type=int,
                           default=int(os.environ.get('CNFSE_LISTEN_PORT', '8080')),
                           help='listen port')
    argparser.add_argument('-i', '--inject-host', type=str, required=not env_inject_host,
                           default=env_inject_host,
                           help='inject host')
    argparser.add_argument('-r', '--prepend-inject-host', action='store_true',
                           default=bool(os.environ.get('CNFSE_PREPEND_INJECT_HOST')),
                           help='prepend injected host instead of append')
    argparser.add_argument('-o', '--override-host', type=str,
                           default=os.environ.get('CNFSE_OVERRIDE_HOST'),
                           help='override request host')
    argparser.add_argument('-X', '--drop-x-headers', action='store_true',
                           default=bool(os.environ.get('CNFSE_DROP_X_HEADERS')),
                           help='drop X-* headers')
    argparser.add_argument('-v', '--verbose', action='store_true',
                           default=bool(os.environ.get('CNFSE_VERBOSE')),
                           help='verbose logging')
    args = argparser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    try:
        import uvloop  # pyright: ignore[reportMissingImports]
        logging.info('Using uvloop')
        uvloop.run(main(args))  # pyright: ignore[reportUnknownMemberType]
    except ImportError:
        asyncio.run(main(args))
