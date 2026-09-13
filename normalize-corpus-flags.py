#!/usr/bin/env python3

"""Prepare a legacy corpus for the flag-based HTTP fuzzer."""

import hashlib
import sys
from pathlib import Path


GET_1 = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"
GET_2 = b"GET /index.html?fuzz=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"


def multipacket_seed(flags):
    data = bytearray([flags])
    for packet in (GET_1, GET_2):
        data.extend(len(packet).to_bytes(2, "big"))
        data.extend(packet)
    return bytes(data)


def valid_multipacket(data):
    offset = 0
    packet_count = 0

    while offset < len(data):
        if len(data) - offset < 2:
            return False
        size = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        if size == 0 or size > len(data) - offset:
            return False
        offset += size
        packet_count += 1
        if packet_count > 64:
            return False

    return packet_count > 0


def normalize(data):
    if not data:
        return data
    result = bytearray(data)
    if result[0] & 0x02 and valid_multipacket(result[1:]):
        flags = result[0] & 0x07
    else:
        flags = 1 if result[0] == 1 else 0
    result[0] = flags
    return bytes(result)


def basic_seeds():
    seeds = [bytes([flags]) + GET_1 for flags in (0x00, 0x01)]
    seeds.extend(multipacket_seed(flags) for flags in (0x02, 0x03, 0x06, 0x07))
    return seeds


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} CORPUS_DIRECTORY")

    corpus = Path(sys.argv[1])
    if not corpus.is_dir():
        raise SystemExit(f"not a directory: {corpus}")

    changed = 0
    empty = 0
    for path in sorted(corpus.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        if not data:
            empty += 1
            continue
        normalized = normalize(data)
        if normalized != data:
            path.write_bytes(normalized)
            changed += 1

    added = 0
    for seed in basic_seeds():
        path = corpus / hashlib.sha1(seed).hexdigest()
        if not path.exists() or path.read_bytes() != seed:
            path.write_bytes(seed)
            added += 1

    print(
        f"normalized {changed} files; added {added} seed inputs; "
        f"skipped {empty} empty files"
    )


if __name__ == "__main__":
    main()
