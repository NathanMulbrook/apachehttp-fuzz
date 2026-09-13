#!/usr/bin/env python3

"""Decode and replay one raw or flag-framed HTTP fuzzer input."""

import argparse
from dataclasses import dataclass
from pathlib import Path
import socket
import sys
import time


HTTP_PRELUDE_FLAG = 0x01
MULTIPACKET_FLAG = 0x02
WAIT_FOR_RESPONSE_FLAG = 0x04
MAX_PACKET_COUNT = 64
KEEPALIVE_PRELUDE = (
    b"HEAD / HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
)


@dataclass(frozen=True)
class FuzzerInput:
    flags: int
    packets: tuple[bytes, ...]

    @property
    def multipacket(self):
        return bool(self.flags & MULTIPACKET_FLAG)


def parse_fuzzer_input(data):
    if not data:
        raise ValueError("empty fuzzer input")
    flags = data[0]
    if not flags & MULTIPACKET_FLAG:
        return FuzzerInput(flags, (data[1:],))

    packets = []
    offset = 1
    while offset < len(data):
        if len(data) - offset < 2:
            raise ValueError("truncated packet length")
        packet_length = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        end = offset + packet_length
        if packet_length == 0 or end > len(data):
            raise ValueError("invalid packet length")
        packets.append(data[offset:end])
        if len(packets) > MAX_PACKET_COUNT:
            raise ValueError("fuzzer input contains more than 64 packets")
        offset = end
    if not packets:
        raise ValueError("multipacket fuzzer input contains no packets")
    return FuzzerInput(flags, tuple(packets))


def receive_response(sock, timeout, limit):
    sock.settimeout(timeout)
    try:
        first = sock.recv(min(4096, limit))
    except socket.timeout:
        return None
    if not first:
        return b""

    response = bytearray(first)
    sock.settimeout(0.05)
    while len(response) < limit:
        try:
            chunk = sock.recv(min(4096, limit - len(response)))
        except socket.timeout:
            break
        if not chunk:
            break
        response.extend(chunk)
    return bytes(response)


def describe_response(label, response):
    if response is None:
        print(f"{label}: no response before timeout")
    elif not response:
        print(f"{label}: connection closed")
    else:
        text = response.decode("latin-1", "backslashreplace")
        print(f"{label}: bytes={len(response)} hex={response.hex()}")
        print(f"{label} text: {text!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="raw HTTP bytes or a fuzzer input")
    parser.add_argument("--raw", action="store_true",
                        help="send the complete file without decoding a control byte")
    parser.add_argument("--packet", type=int, metavar="N",
                        help="replay only packet N from a multipacket fuzzer input")
    parser.add_argument("--host", default="::1")
    parser.add_argument("--port", type=int, default=5801)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--response-wait-ms", type=float, default=500.0)
    parser.add_argument("--packet-delay-ms", type=float, default=20.0)
    parser.add_argument("--response-limit", type=int, default=65536)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.raw and args.packet is not None:
        parser.error("--raw and --packet cannot be used together")
    if not 1 <= args.port <= 65535:
        parser.error("invalid port")
    if args.timeout <= 0 or args.response_wait_ms <= 0 or args.packet_delay_ms < 0:
        parser.error("invalid timeout or delay")
    if not 1 <= args.response_limit <= 1 << 20:
        parser.error("invalid response limit")

    data = args.input.read_bytes()
    if args.raw:
        decoded = FuzzerInput(0, (data,))
    else:
        decoded = parse_fuzzer_input(data)

    packets = decoded.packets
    if args.packet is not None:
        if not decoded.multipacket:
            parser.error("--packet requires a multipacket input")
        if not 1 <= args.packet <= len(packets):
            parser.error(f"--packet must be between 1 and {len(packets)}")
        packets = (packets[args.packet - 1],)

    print(
        f"flags=0x{decoded.flags:02x} prelude={int(bool(decoded.flags & HTTP_PRELUDE_FLAG))} "
        f"multipacket={int(decoded.multipacket)} "
        f"wait={int(bool(decoded.flags & WAIT_FOR_RESPONSE_FLAG))} "
        f"packets={len(decoded.packets)} selected={len(packets)} "
        f"sizes={','.join(str(len(packet)) for packet in packets)}"
    )
    if args.dry_run:
        return 0

    with socket.create_connection((args.host, args.port), timeout=args.timeout) as sock:
        if decoded.flags & HTTP_PRELUDE_FLAG:
            sock.sendall(KEEPALIVE_PRELUDE)
            response = receive_response(sock, args.timeout, args.response_limit)
            describe_response("prelude response", response)
            if not response:
                print("prelude response failed; sequence stopped", file=sys.stderr)
                return 2

        for index, packet in enumerate(packets, 1):
            sock.sendall(packet)
            print(f"packet {index}/{len(packets)}: sent {len(packet)} bytes")
            if index < len(packets):
                if decoded.flags & WAIT_FOR_RESPONSE_FLAG:
                    response = receive_response(
                        sock, args.response_wait_ms / 1000.0, args.response_limit)
                    describe_response(f"packet {index} gate", response)
                    if not response:
                        print("response gate failed; sequence stopped", file=sys.stderr)
                        return 2
                else:
                    time.sleep(args.packet_delay_ms / 1000.0)

        response = receive_response(sock, args.timeout, args.response_limit)
        describe_response("final response", response)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
