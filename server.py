#!/usr/bin/env python3

import argparse
import asyncio
from typing import Optional

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived


class EchoProtocol(QuicConnectionProtocol):
    """A minimal QUIC echo protocol.

    For every received stream fragment, immediately echo it back on the same stream.
    """

    def quic_event_received(self, event: QuicEvent) -> None:  # type: ignore[override]
        if isinstance(event, StreamDataReceived):
            # Echo back the bytes and mirror end_stream so the client sees EOF.
            self._quic.send_stream_data(event.stream_id, event.data, end_stream=event.end_stream)
            self.transmit()


async def main(host: str, port: int, certificate: str, private_key: str, secrets_log: Optional[str]) -> None:
    # Configure QUIC with a self-signed certificate. ALPN "hq-29" is fine for a raw QUIC demo.
    configuration = QuicConfiguration(is_client=False, alpn_protocols=["hq-29"])  # type: ignore[arg-type]
    configuration.load_cert_chain(certificate, private_key)

    # Optional: write TLS secrets for Wireshark decryption.
    if secrets_log:
        configuration.secrets_log_file = open(secrets_log, "a")

    server = await serve(
        host,
        port,
        configuration=configuration,
        create_protocol=EchoProtocol,
        retry=False,
    )
    print(f"QUIC echo server listening on {host}:{port}")

    try:
        # Run until Ctrl+C
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Minimal QUIC echo server (aioquic)")
    parser.add_argument("--host", default="127.0.0.1", help="Listen address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=4433, help="UDP port (default: 4433)")
    parser.add_argument("--certificate", default="quic.crt", help="Path to certificate (PEM)")
    parser.add_argument("--private-key", dest="private_key", default="quic.key", help="Path to private key (PEM)")
    parser.add_argument("--secrets-log", default="ssl_keylog.txt", help="Optional TLS secrets log file for Wireshark")
    args = parser.parse_args()

    asyncio.run(main(args.host, args.port, args.certificate, args.private_key, args.secrets_log))
