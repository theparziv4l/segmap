#!/usr/bin/env python3
"""SegMap egress listener (PCI DSS 1.3.2). Run on a VPS you control, outside the entity's network.

Every TCP connection immediately receives "SEGMAP-EGRESS <token>". SegMap's egress check counts a port
as open only if nmap's banner script sees that token, so transparent proxies / SYN proxies that merely
answer the handshake do not count.

    python3 egress_listener.py --token MYTOKEN --port 9999
    # send every TCP port except your SSH port to the listener:
    iptables -t nat -A PREROUTING -p tcp -m multiport ! --dports 22 -j REDIRECT --to-ports 9999

(Move sshd to a high port first if you want port 22 tested too.)
"""
import argparse
import asyncio
import re


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", required=True)
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--bind", default="0.0.0.0")
    a = ap.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", a.token):
        raise SystemExit("token: letters, digits, _ and - only")
    banner = f"SEGMAP-EGRESS {a.token}\r\n".encode()

    async def handle(reader, writer):
        peer = writer.get_extra_info("peername")
        try:
            sock = writer.get_extra_info("socket")
            # original destination port survives REDIRECT via SO_ORIGINAL_DST; log it when available
            try:
                import socket
                import struct
                raw = sock.getsockopt(socket.SOL_IP, 80, 16)  # SO_ORIGINAL_DST
                dport = struct.unpack("!2xH4x8x", raw)[0]
            except OSError:
                dport = a.port
            print(f"{peer[0]} -> tcp/{dport}", flush=True)
            writer.write(banner)
            await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(handle, a.bind, a.port)
    print(f"listening on {a.bind}:{a.port}, token {a.token}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
