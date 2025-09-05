#!/usr/bin/env python3

import argparse
import asyncio
import ssl
from typing import Optional

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived


class SimpleClient(QuicConnectionProtocol):
    """A tiny QUIC client that sends one message and collects the echo."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()

    def quic_event_received(self, event: QuicEvent) -> None:  # type: ignore[override]
        if isinstance(event, StreamDataReceived):
            # Collect echoed data from the server
            self._queue.put_nowait(event.data)

    async def send_and_receive(self, data: bytes) -> bytes:
        stream_id = self._quic.get_next_available_stream_id()
        self._quic.send_stream_data(stream_id, data, end_stream=True)
        self.transmit()
        return await asyncio.wait_for(self._queue.get(), timeout=5.0)


async def main(host: str, port: int, message: str, secrets_log: Optional[str]) -> None:
    # Client QUIC configuration. We disable cert verification for this local demo.
    configuration = QuicConfiguration(is_client=True, alpn_protocols=["hq-29"])  # type: ignore[arg-type]
    configuration.verify_mode = ssl.CERT_NONE  # trust our self-signed server for the demo

    # Optional: write TLS secrets for Wireshark decryption.
    if secrets_log:
        configuration.secrets_log_file = open(secrets_log, "a")

    async with connect(host, port, configuration=configuration, create_protocol=SimpleClient) as client:
        proto: SimpleClient = client  # type: ignore[assignment]
        data = await proto.send_and_receive(message.encode("utf-8"))
        print(data.decode("utf-8"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Minimal QUIC client (aioquic)")
    parser.add_argument("--host", default="127.0.0.1", help="Server address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=4433, help="UDP port (default: 4433)")
    parser.add_argument("--message", default="Hello on QUIC Protocol!", help="Message to send")
    parser.add_argument("--secrets-log", default="ssl_keylog.txt", help="Optional TLS secrets log file for Wireshark")
    args = parser.parse_args()

    asyncio.run(main(args.host, args.port, args.message, args.secrets_log))
