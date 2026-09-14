#!/usr/bin/env python3

"""Create focused HTTP seeds for the multipacket fuzzer."""

import argparse
import gzip
from pathlib import Path


def request(method, target="/", headers=(), body=b"", version="HTTP/1.1"):
    if isinstance(body, str):
        body = body.encode()
    lines = [f"{method} {target} {version}", "Host: localhost", *headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def raw(packet, flags=0x00):
    return bytes([flags]) + packet


def multipacket(*packets, flags=0x02):
    result = bytearray([flags])
    for packet in packets:
        if not packet or len(packet) > 0xFFFF:
            raise ValueError("multipacket frames must contain 1 through 65535 bytes")
        result.extend(len(packet).to_bytes(2, "big"))
        result.extend(packet)
    if not packets:
        raise ValueError("multipacket input needs at least one packet")
    return bytes(result)


def h2_frame(frame_type, flags, stream, payload=b""):
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + (stream & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


def h2_request_headers(stream, path=b"/"):
    if not path or len(path) > 0x7F:
        raise ValueError("HTTP/2 seed path must contain 1 through 127 bytes")
    block = b"\x82\x86\x04" + bytes([len(path)]) + path
    block += b"\x01\x09localhost"
    return h2_frame(0x01, 0x05, stream, block)


def tls_record(content_type, payload, version=b"\x03\x03"):
    return bytes([content_type]) + version + len(payload).to_bytes(2, "big") + payload


def tls_extension(number, value):
    return number.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def tls_alpn(protocols):
    encoded = bytearray()
    for protocol in protocols:
        if not 1 <= len(protocol) <= 255:
            raise ValueError("TLS ALPN protocol names must contain 1 through 255 bytes")
        encoded.append(len(protocol))
        encoded.extend(protocol)
    if not encoded or len(encoded) > 0xFFFF:
        raise ValueError("TLS ALPN protocol list must contain 1 through 65535 bytes")
    return len(encoded).to_bytes(2, "big") + encoded


def tls_client_hello(protocols=(b"h2", b"http/1.1")):
    name = b"localhost"
    server_name = len(name + b"\0\0\0").to_bytes(2, "big")
    server_name += b"\0" + len(name).to_bytes(2, "big") + name
    alpn = tls_alpn(protocols)
    groups = b"\x00\x04\x00\x1d\x00\x17"
    signatures = b"\x00\x08\x08\x04\x04\x03\x08\x05\x04\x01"
    key = bytes(range(1, 33))
    key_share_entry = b"\x00\x1d" + len(key).to_bytes(2, "big") + key
    key_share = len(key_share_entry).to_bytes(2, "big") + key_share_entry
    extensions = b"".join((
        tls_extension(0x0000, server_name),
        tls_extension(0x0010, alpn),
        tls_extension(0x000A, groups),
        tls_extension(0x000D, signatures),
        tls_extension(0x002B, b"\x02\x03\x04"),
        tls_extension(0x002D, b"\x01\x01"),
        tls_extension(0x0033, key_share),
    ))
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + b"\x00\x08\x13\x01\x13\x02\x13\x03\xc0\x2f"
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return tls_record(0x16, handshake, b"\x03\x01")


def tls12_client_hello():
    name = b"localhost"
    server_name = len(name + b"\0\0\0").to_bytes(2, "big")
    server_name += b"\0" + len(name).to_bytes(2, "big") + name
    protocols = b"\x08http/1.1\x02h2"
    extensions = b"".join((
        tls_extension(0x0000, server_name),
        tls_extension(0x0010, len(protocols).to_bytes(2, "big") + protocols),
        tls_extension(0x000A, b"\x00\x06\x00\x17\x00\x18\x00\x1d"),
        tls_extension(0x000B, b"\x01\x00"),
        tls_extension(0x000D, b"\x00\x08\x04\x03\x05\x03\x04\x01\x02\x01"),
        tls_extension(0x0A0A, b""),
    ))
    body = (
        b"\x03\x03" + bytes(reversed(range(32))) + b"\x00"
        + b"\x00\x08\xc0\x2f\xc0\x2b\xcc\xa8\x00\x9c"
        + b"\x01\x00" + len(extensions).to_bytes(2, "big") + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return tls_record(0x16, handshake, b"\x03\x01")


def sslv2_client_hello():
    body = (
        b"\x01\x03\x01" + b"\x00\x06" + b"\x00\x00" + b"\x00\x10"
        + b"\x00\x00\x2f\x00\x00\x35" + bytes(range(16))
    )
    length = len(body)
    return bytes([0x80 | (length >> 8), length & 0xFF]) + body


def corpus_seeds():
    get = request("GET", "/")
    head = request("HEAD", "/index.html", ("Connection: keep-alive",))
    options = request("OPTIONS", "*", ("Connection: keep-alive",))

    chunk_headers = request(
        "POST", "/upload",
        ("Transfer-Encoding: chunked", "Trailer: X-Checksum", "Content-Type: text/plain"),
    )
    expect_headers = request(
        "POST", "/upload",
        ("Content-Length: 11", "Expect: 100-continue", "Content-Type: text/plain"),
    )
    h2_settings = h2_frame(0x04, 0x00, 0, b"\x00\x03\x00\x00\x00\x64")
    h2_headers = h2_request_headers(1)
    h2_ping = h2_frame(0x06, 0x00, 0, b"fuzzhttp")
    h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    h2_upgrade = request(
        "GET", "/h2c",
        ("Connection: Upgrade, HTTP2-Settings", "Upgrade: h2c",
         "HTTP2-Settings: AAMAAABkAAQAAP__"),
    )
    hello = tls_client_hello()
    hello12 = tls12_client_hello()
    hello_h2_only = tls_client_hello((b"h2",))
    longest_alpn_name = b"fuzz-" + b"a" * 250
    hello_alpn_boundary = tls_client_hello((longest_alpn_name, b"h2"))
    gzip_body = gzip.compress(b"fuzz input filter\n" * 4, mtime=0)
    gzip_bad_crc = gzip_body[:-8] + bytes(byte ^ 0xFF for byte in gzip_body[-8:])
    gzip_members = gzip.compress(b"first fuzz member\n", mtime=0)
    gzip_members += gzip.compress(b"second fuzz member\n", mtime=0)
    form_body = b"httpd_username=fuzz&httpd_password=fuzz&login=Login"
    proppatch_body = (
        b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:F="urn:fuzz">'
        b'<D:set><D:prop><F:value>fuzz</F:value></D:prop></D:set></D:propertyupdate>'
    )
    propfind_lock_body = (
        b'<D:propfind xmlns:D="DAV:"><D:prop><D:lockdiscovery/>'
        b'<D:supportedlock/></D:prop></D:propfind>'
    )
    balancer_manager_body = (
        b"b=managed&w=http%3A%2F%2F%5B%3A%3A1%5D%3A6827&nonce=fuzz"
        b"&w_lf=1.25&w_ls=1&w_wr=one&w_status_I=0&w_status_N=0"
        b"&w_status_D=0&b_lbm=byrequests&b_tmo=1&b_max=2&b_sforce=0"
        b"&b_ss=FUZZROUTE&xml=1"
    )

    return {
        "seed-get-index": raw(get),
        "seed-prelude-get": raw(request("GET", "/status?full=1", ("Accept: */*",)), 0x01),
        "seed-options-star": raw(options),
        "seed-http10-keepalive": raw(request(
            "GET", "/index.html", ("Connection: keep-alive",), version="HTTP/1.0")),
        "seed-path-parsing": raw(request(
            "GET", "/a/../b/%2e%2e/%252e%252e//c;param?x=%00&x=%ff&empty=" ,
            ("Accept: text/html, application/json;q=0.9, */*;q=0.1",))),
        "seed-header-boundaries": raw(request(
            "GET", "/headers",
            ("Host: [::1]:5800", "X-Empty:", "X-Spaces:    a\tb   ",
             "X-Duplicate: first", "X-Duplicate: second", "TE: trailers",
             "Connection: keep-alive, X-Hop", "X-Hop: remove-me"))),
        "seed-content-length-boundary": raw(request(
            "POST", "/upload",
            ("Content-Length: 4", "Content-Length: 4", "Content-Type: application/octet-stream"),
            b"test")),
        "seed-cl-te-conflict": raw(request(
            "POST", "/upload",
            ("Content-Length: 4", "Transfer-Encoding: chunked"), b"0\r\n\r\n")),
        "seed-pipeline-one-write": raw(
            request("GET", "/one", ("Connection: keep-alive",))
            + request("HEAD", "/two", ("Connection: close",))),
        "seed-keepalive-fixed": multipacket(get, head, options, flags=0x03),
        "seed-keepalive-wait": multipacket(
            request("GET", "/one", ("Connection: keep-alive",)),
            request("GET", "/two?x=1", ("Connection: keep-alive",)),
            request("HEAD", "/missing", ("Connection: close",)), flags=0x07),
        "seed-chunk-split": multipacket(
            chunk_headers, b"5\r\nhello\r\n", b"6;name=value\r\n world\r\n",
            b"0\r\nX-Checksum: 0123456789abcdef\r\n\r\n", flags=0x03),
        "seed-chunk-boundaries": raw(request(
            "POST", "/upload", ("Transfer-Encoding: chunked",),
            b"1;foo=bar\r\na\r\n0000000000000001\r\nb\r\n0\r\n\r\n")),
        "seed-chunk-offt-max": multipacket(
            chunk_headers, b"0000000000000000",
            b"7fffffffffffffff;edge=max\r\n", flags=0x02),
        "seed-chunk-offt-overflow": multipacket(
            chunk_headers, b"0000000000000000",
            b"8000000000000000;edge=overflow\r\n", flags=0x02),
        "seed-chunk-width-rejected": multipacket(
            chunk_headers, b"1000000000000000",
            b"0;edge=width\r\n", flags=0x02),
        "seed-chunk-extensions-trailers": multipacket(
            request("POST", "/upload", (
                "Transfer-Encoding: chunked",
                "Trailer: X-Fuzz-Checksum, X-Fuzz-Duplicate",
                "Content-Type: application/octet-stream")),
            b"000000000000000a;token=value;quoted=\"a\\\"b\"\r\n",
            b"0123456789\r\n1;flag\r\nZ\r\n",
            b"000;last=yes\r\nX-Fuzz-Checksum: 0123456789abcdef\r\n"
            b"X-Fuzz-Duplicate: one\r\nX-Fuzz-Duplicate: two\r\n\r\n",
            flags=0x02),
        "seed-expect-continue": multipacket(expect_headers, b"hello world", flags=0x07),
        "seed-range-conditional": multipacket(
            request("GET", "/index.html", ("Range: bytes=0-0,-1,2-4,999999-",)),
            request("GET", "/index.html", ("If-None-Match: \"fuzz-etag\"",)),
            request("GET", "/index.html", (
                "If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT",
                "If-Range: Wed, 21 Oct 2015 07:28:00 GMT", "Range: bytes=1-2")),
            flags=0x07),
        "seed-auth-schemes": multipacket(
            request("GET", "/auth/basic", ("Authorization: Basic ZnV6ejpmdXp6",)),
            request("GET", "/auth/digest", (
                'Authorization: Digest username="fuzz", realm="fuzz", nonce="00", '
                'uri="/auth/digest", response="00000000000000000000000000000000", '
                'algorithm=MD5, qop=auth, nc=00000001, cnonce="ff"',)),
            request("GET", "/auth/basic", ("Authorization: Bearer a.b.c",)), flags=0x03),
        "seed-rewrite-paths": multipacket(
            request("GET", "/tenant/a/b?name=value", (
                "Host: blue.fuzz.test", "Forwarded: for=\"[::1]\";proto=http",
                "X-Forwarded-For: ::1", "X-Fuzz-Input: rewrite")),
            request("GET", "/%2f%2e%2e/%2e/%3f/%23?q=a+b%26c"),
            request("GET", "/index.html/path/info;matrix=1"), flags=0x03),
        "seed-proxy-forms": multipacket(
            request("GET", "/proxy/index.txt", ("Proxy-Connection: keep-alive",)),
            b"GET http://[::1]:6810/backend/index.txt HTTP/1.1\r\n"
            b"Host: [::1]:6810\r\nProxy-Connection: keep-alive\r\n\r\n",
            request("OPTIONS", "http://[::1]:6810/*", ("Max-Forwards: 0",)), flags=0x02),
        "seed-proxy-balancer-websocket": multipacket(
            request("GET", "/balancer/index.txt", ("Connection: keep-alive",)),
            request("GET", "/socket/", (
                "Connection: Upgrade", "Upgrade: websocket", "Sec-WebSocket-Version: 13",
                "Sec-WebSocket-Key: ZHVtbXlrZXlkdW1teWs=")),
            request("GET", "/combined-proxy/index.txt"), flags=0x07),
        "seed-content-filters": multipacket(
            request("GET", "/index.txt", ("Accept-Encoding: br, gzip;q=0.8, identity;q=0.1",)),
            request("GET", "/substitute/index.txt", ("Accept-Encoding: gzip, br",)),
            request("GET", "/include.shtml", ("Accept-Encoding: br",)), flags=0x07),
        "seed-deflate-input-stream": multipacket(
            request("POST", "/inflate", (
                "Content-Encoding: gzip", "Content-Type: application/octet-stream",
                f"Content-Length: {len(gzip_body)}")),
            gzip_body[:10], gzip_body[10:-8], gzip_body[-8:], flags=0x02),
        "seed-deflate-input-bad-crc": raw(request(
            "POST", "/inflate", (
                "Content-Encoding: gzip", f"Content-Length: {len(gzip_bad_crc)}"),
            gzip_bad_crc)),
        "seed-deflate-input-truncated": raw(request(
            "POST", "/inflate", (
                "Content-Encoding: gzip", f"Content-Length: {len(gzip_body) - 5}"),
            gzip_body[:-5])),
        "seed-deflate-input-errors": raw(request(
            "POST", "/inflate", (
                "Content-Encoding: gzip", f"Content-Length: {len(gzip_members) + 3}"),
            gzip_members + b"bad")),
        "seed-sed-stream-boundaries": multipacket(
            request("POST", "/sed", (
                "Content-Type: text/plain", "Content-Length: 31")),
            b"prefix-fu", b"zz-middle-f", b"uzz-suffix\n", flags=0x02),
        "seed-cache-validators": multipacket(
            request("GET", "/index.txt", ("Cache-Control: max-age=0, no-cache",)),
            request("GET", "/index.txt", ("Cache-Control: only-if-cached", "Age: 2147483647")),
            request("PURGE", "/index.txt", ("Cache-Control: no-store",)), flags=0x07),
        "seed-cache-socache": multipacket(
            request("GET", "/socache/index.txt", ("Accept-Encoding: identity",)),
            request("HEAD", "/socache/index.txt", ("Cache-Control: max-age=0",)),
            request("GET", "/socache/index.txt", (
                "Range: bytes=0-3", "If-None-Match: \"fuzz-socache\"")),
            request("GET", "/socache/index.txt", ("Cache-Control: no-cache, no-store",)),
            flags=0x07),
        "seed-negotiation-index": multipacket(
            request("GET", "/variant", (
                "Accept-Language: fr-CA, fr;q=0.9, en;q=0.1", "Accept-Charset: utf-8")),
            request("GET", "/INDEX.TxT", ("Accept: text/plain",)),
            request("GET", "/", ("Accept-Language: *;q=0",)), flags=0x07),
        "seed-cgi-body": multipacket(
            request("GET", "/cgi-bin/echo.cgi?a=%00&b=1&b=2"),
            request("POST", "/cgi-bin/echo.cgi", (
                "Content-Type: application/x-www-form-urlencoded", "Content-Length: 17"),
                b"a=one&b=two%00end"),
            request("GET", "/include.shtml"), flags=0x07),
        "seed-ssi-actions": multipacket(
            request("GET", "/complex.shtml", (
                "Accept-Encoding: gzip", "X-Fuzz-SSI: <!--#echo var=REQUEST_METHOD -->")),
            request("POST", "/action.fuzz?x=1", (
                "Content-Type: application/x-www-form-urlencoded", "Content-Length: 11"),
                b"fuzz=action"), flags=0x07),
        "seed-handlers-status-reflect": multipacket(
            request("GET", "/server-status?auto"),
            request("GET", "/server-info?list"),
            request("POST", "/reflect", ("Content-Length: 8", "X-Reflect: yes"), b"reflect!"),
            request("TRACE", "/trace", ("Max-Forwards: 1",)), flags=0x07),
        "seed-trace-max-forwards": multipacket(
            request("TRACE", "/trace?headers=1", (
                "Connection: keep-alive", "Max-Forwards: 0", "X-Trace-Empty:",
                "X-Trace-Duplicate: one", "X-Trace-Duplicate: two", "TE: trailers")),
            request("TRACE", "http://[::1]:6810/trace", (
                "Connection: keep-alive", "Max-Forwards: 0000000000000000000")),
            request("TRACE", "http://[::1]:6810/trace", (
                "Connection: close", "Max-Forwards: 9223372036854775807")),
            flags=0x07),
        "seed-trace-chunked-body": multipacket(
            request("TRACE", "/trace/body", (
                "Connection: close", "Transfer-Encoding: chunked",
                "Trailer: X-Trace-Trailer", "X-Trace-Body: chunked")),
            b"4;trace=yes\r\nbody\r\n",
            b"5;part=two\r\nfuzz!\r\n",
            b"0\r\nX-Trace-Trailer: complete\r\n\r\n",
            flags=0x02),
        "seed-request-line-modes": multipacket(
            b"GET /old-style\r\n",
            b"GET\t/tabbed\tHTTP/1.1\nHost: localhost\n\n",
            b"FUZZ-METHOD /registered HTTP/1.1\r\nHost: localhost\r\n\r\n",
            b"GET /folded HTTP/1.1\r\nHost: localhost\r\nX-Fold: first\r\n second\r\n\r\n",
            flags=0x02),
        "seed-webdav-propfind": raw(request(
            "PROPFIND", "/dav/", ("Depth: infinity", "Content-Type: application/xml; charset=utf-8",
                                  "Content-Length: 107"),
            b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:getetag/><D:resourcetype/></D:prop></D:propfind>')),
        "seed-webdav-stateful": multipacket(
            request("OPTIONS", "/dav/"),
            request("MKCOL", "/dav/fuzz-collection"),
            request("PUT", "/dav/fuzz-collection/item", ("Content-Length: 4",), b"data"),
            request("COPY", "/dav/fuzz-collection/item", (
                "Destination: http://localhost/dav/fuzz-collection/copy", "Overwrite: T", "Depth: 0")),
            request("MOVE", "/dav/fuzz-collection/copy", (
                "Destination: http://localhost/dav/fuzz-collection/moved", "Overwrite: F")),
            request("DELETE", "/dav/fuzz-collection", ("Depth: infinity",)), flags=0x07),
        "seed-webdav-lock": raw(request(
            "LOCK", "/dav/fuzz-lock", ("Timeout: Second-1", "Depth: 0",
                                       "Content-Type: application/xml", "Content-Length: 160"),
            b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner>fuzz</D:owner></D:lockinfo>')),
        "seed-webdav-properties": multipacket(
            request("PROPPATCH", "/dav/seed.txt", (
                "Content-Type: application/xml",
                f"Content-Length: {len(proppatch_body)}"), proppatch_body),
            request("PROPFIND", "/dav/seed.txt", (
                "Depth: 0", "Content-Type: application/xml",
                f"Content-Length: {len(propfind_lock_body)}"), propfind_lock_body),
            request("GET", "/dav/?C=N;O=D;F=0;V=1;P=*.txt"), flags=0x07),
        "seed-webdav-destination-ports": multipacket(
            request("PUT", "/dav/source8", ("Content-Length: 4",), b"fuzz"),
            request("COPY", "/dav/source8", (
                "Destination: http://localhost:5808/dav/copy8", "Overwrite: T", "Depth: 0")),
            request("MOVE", "/dav/copy8", (
                "Destination: http://localhost:5808/dav/moved8", "Overwrite: T")),
            request("PUT", "/dav/source19", ("Content-Length: 4",), b"fuzz"),
            request("COPY", "/dav/source19", (
                "Destination: http://localhost:5819/dav/copy19", "Overwrite: T", "Depth: 0")),
            request("MOVE", "/dav/copy19", (
                "Destination: http://localhost:5819/dav/moved19", "Overwrite: T")),
            flags=0x07),
        "seed-h2c-prior-knowledge": raw(
            h2_preface + h2_settings + h2_frame(0x08, 0x00, 0, b"\x00\x01\x00\x00")
            + h2_ping + h2_headers),
        "seed-h2c-upgrade": multipacket(
            h2_upgrade, h2_preface + h2_settings, h2_request_headers(3), flags=0x06),
        "seed-h2-frame-boundaries": multipacket(
            h2_preface, h2_settings[:5], h2_settings[5:], h2_ping, h2_headers, flags=0x02),
        "seed-h2-control-matrix": raw(
            h2_preface
            + h2_frame(0x04, 0x00, 0,
                       b"\x00\x01\x00\x00\x00\x00"
                       b"\x00\x02\x00\x00\x00\x01"
                       b"\x00\x04\x7f\xff\xff\xff"
                       b"\x00\xff\xde\xad\xbe\xef")
            + h2_frame(0x04, 0x01, 0)
            + h2_frame(0x06, 0x00, 0, b"fuzzping")
            + h2_frame(0x06, 0x01, 0, b"fuzzping")
            + h2_frame(0x08, 0x00, 0, b"\x00\x01\x00\x00")
            + h2_frame(0x02, 0x00, 1, b"\x00\x00\x00\x00\xff")
            + h2_request_headers(1, b"/h2-push")
            + h2_frame(0x08, 0x00, 1, b"\x00\x00\x10\x00")
            + h2_request_headers(3, b"/index.txt")
            + h2_frame(0x03, 0x00, 3, b"\x00\x00\x00\x08")
            + h2_frame(0x07, 0x00, 0, b"\x00\x00\x00\x00\x00\x00\x00\x00fuzz")),
        "seed-h2-window-error": raw(
            h2_preface + h2_settings + h2_request_headers(1)
            + h2_frame(0x08, 0x00, 1, b"\x00\x00\x00\x00")),
        "seed-h2-priority-error": raw(
            h2_preface + h2_settings
            + h2_frame(0x02, 0x00, 1, b"\x00\x00\x00\x01\x0f")),
        "seed-h2-continuation": raw(
            h2_preface + h2_settings
            + h2_frame(0x01, 0x01, 1, b"\x82\x86\x04\x08/h2-")
            + h2_frame(0x09, 0x04, 1, b"push\x01\x09localhost")),
        "seed-h2-websocket-connect": raw(
            h2_preface + h2_settings
            + h2_frame(0x01, 0x05, 1,
                       b"\x02\x07CONNECT\x00\x09:protocol\x09websocket"
                       b"\x86\x04\x08/socket/\x01\x09localhost")),
        "seed-tls-clienthello": raw(hello),
        "seed-tls-alpn-h2-only": raw(hello_h2_only),
        "seed-tls-alpn-name-boundary": raw(hello_alpn_boundary),
        "seed-tls-record-split": multipacket(hello[:5], hello[5:41], hello[41:], flags=0x02),
        "seed-tls12-clienthello": raw(hello12),
        "seed-tls-fragmented-handshake": raw(
            tls_record(0x16, hello[5:29], b"\x03\x01")
            + tls_record(0x16, hello[29:], b"\x03\x03")),
        "seed-tls-unexpected-ccs": raw(tls_record(0x14, b"\x01")),
        "seed-tls-alert": raw(tls_record(0x15, b"\x02\x28")),
        "seed-tls-bad-length": raw(
            tls_record(0x16, b"\x01\xff\xff\xff") + b"\x16\x03\x03\xff\xff"),
        "seed-tls-record-matrix": raw(
            tls_record(0x16, b"", b"\x03\x01")
            + tls_record(0x16, b"", b"\x03\x03")
            + tls_record(0x14, b"\x01")),
        "seed-sslv2-clienthello": raw(sslv2_client_hello()),
        "seed-auth-cache-form-session": multipacket(
            request("GET", "/auth/basic", ("Authorization: Basic ZnV6ejpmdXp6",)),
            request("GET", "/auth/basic", ("Authorization: Basic ZnV6ejpmdXp6",)),
            request("POST", "/auth/login", (
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(form_body)}"), form_body),
            request("GET", "/auth/form", (
                "Cookie: fuzz-session=Zm9vPWJhciZ1c2VyPWZ1eno=; duplicate=one; duplicate=two",)),
            flags=0x07),
        "seed-proxy-connect-tunnel": multipacket(
            b"CONNECT [::1]:6810 HTTP/1.1\r\nHost: [::1]:6810\r\n\r\n",
            request("GET", "/index.txt", ("Connection: close",)), flags=0x06),
        "seed-proxy-ajp": raw(request("POST", "/proxy-ajp/fuzz", (
            "Content-Type: application/octet-stream", "Content-Length: 4"), b"fuzz")),
        "seed-proxy-fcgi": raw(request("POST", "/proxy-fcgi/fuzz", (
            "Content-Type: application/x-www-form-urlencoded", "Content-Length: 7"), b"x=fuzz!")),
        "seed-proxy-scgi": raw(request("GET", "/proxy-scgi/fuzz?x=1", (
            "X-Fuzz-SCGI: yes",))),
        "seed-proxy-uwsgi": raw(request("GET", "/proxy-uwsgi/fuzz/path", (
            "X-Fuzz-UWSGI: yes",))),
        "seed-autoindex-query": multipacket(
            request("GET", "/?C=N;O=D;F=0;V=1;P=*.txt"),
            request("GET", "/?C=S;O=A;F=2;V=0;P=%5Bfuzz%5D*"), flags=0x07),
        "seed-authz-providers": multipacket(
            request("GET", "/auth/anon", (
                "Authorization: Basic YW5vbnltb3VzOmZ1enpAZXhhbXBsZS5jb20=",)),
            request("GET", "/auth/anon", (
                "Authorization: Basic ZnRwOm5vdC1hbi1lbWFpbA==",)),
            request("GET", "/auth/group", (
                "Authorization: Basic YWRtaW46ZnV6eg==",)),
            request("GET", "/auth/owner", (
                "Authorization: Basic YWRtaW46ZnV6eg==",)), flags=0x07),
        "seed-buffer-filter-pipeline": multipacket(
            request("POST", "/buffer", (
                "Content-Type: application/octet-stream", "Content-Length: 65",
                "X-Fuzz-Reflect: one", "X-Fuzz-Echo: two")),
            b"A" * 31, b"B" * 2, b"C" * 32, flags=0x02),
        "seed-rate-limit-output": multipacket(
            request("GET", "/rate/large.txt", ("Range: bytes=0-31,4095-4097",)),
            request("HEAD", "/rate/large.txt", ("Accept-Encoding: identity",)),
            flags=0x07),
        "seed-ext-filter-lifecycle": multipacket(
            request("POST", "/ext/in", (
                "Content-Type: application/octet-stream", "Content-Length: 33")),
            b"fuzz-ext-input-" + b"x" * 18,
            request("GET", "/ext/out/index.txt", ("Accept: application/octet-stream",)),
            flags=0x02),
        "seed-vhost-userdir": multipacket(
            b"GET /index.txt HTTP/1.1\r\nHost: blue.vhost.fuzz.test\r\n\r\n",
            b"GET /~fuzz/index.txt HTTP/1.1\r\nHost: users.fuzz.test\r\n\r\n",
            b"GET /~missing/%2e%2e/index.txt HTTP/1.1\r\n"
            b"Host: users.fuzz.test:5824\r\n\r\n", flags=0x07),
        "seed-rewrite-map-matrix": multipacket(
            request("GET", "/map/txt/hit"),
            request("GET", "/map/txt/missing"),
            request("GET", "/map/dbm/dbm"),
            request("GET", "/map/int/FUZZ.TXT"),
            request("GET", "/map/escape/a%20b%3fc"), flags=0x07),
        "seed-proxy-express-hosts": multipacket(
            b"GET /index.txt HTTP/1.1\r\nHost: express.fuzz.test\r\n\r\n",
            b"GET http://express.fuzz.test/index.txt HTTP/1.1\r\n"
            b"Host: blue.express.fuzz.test\r\n\r\n",
            b"GET /missing HTTP/1.1\r\nHost: missing.express.fuzz.test:5826\r\n\r\n",
            flags=0x07),
        "seed-balancer-methods": multipacket(
            request("GET", "/traffic/index.txt", ("Cookie: FUZZROUTE=.one",)),
            request("GET", "/traffic/index.txt", ("Cookie: FUZZROUTE=.two",)),
            request("GET", "/busy/index.txt"),
            request("GET", "/busy/missing?repeat=1"), flags=0x07),
        "seed-balancer-manager": multipacket(
            request("GET", "/balancer-manager?b=managed&xml=1"),
            request("GET", "/balancer-manager?b=managed&w=bad%3A%2F%2Fvalue&dw=1", (
                "Referer: http://localhost/balancer-manager",)),
            request("POST", "/balancer-manager", (
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(balancer_manager_body)}",
                "Referer: http://localhost/balancer-manager"),
                balancer_manager_body), flags=0x07),
        "seed-error-subrequests": multipacket(
            request("GET", "/missing/error-document"),
            request("PUT", "/index.txt", ("Content-Length: 0",)),
            request("GET", "/fallback-zone/missing/path/info"),
            request("GET", "/fallback-zone/subdir"),
            request("GET", "/fallback-zone/subdir/"), flags=0x07),
        "seed-cache-policy-lock": multipacket(
            request("GET", "/cache-policy/index.txt?session=one", (
                "Cache-Control: private, no-store",)),
            request("GET", "/cache-policy/index.txt?session=two", (
                "Cache-Control: only-if-cached, max-stale=999999",)),
            request("GET", "/cache-policy/index.txt", (
                "Range: bytes=0-0", "If-None-Match: \"fuzz-policy\"")), flags=0x07),
        "seed-proxy-response-rewrite": multipacket(
            b"GET /response/redirect HTTP/1.1\r\nHost: frontend.fuzz.test\r\n\r\n",
            b"GET /response/error/fuzz HTTP/1.1\r\nHost: frontend.fuzz.test\r\n\r\n",
            b"GET /response/destination/index.txt HTTP/1.1\r\n"
            b"Host: frontend.fuzz.test\r\nCookie: id=fuzz\r\n"
            b"Range: bytes=0-3\r\n\r\n", flags=0x07),
        "seed-data-filter-lengths": multipacket(
            request("GET", "/data/length-0.txt"),
            request("GET", "/data/length-1.bin"),
            request("GET", "/data/length-2.txt"),
            request("GET", "/data/length-3.bin"),
            request("GET", "/data/length-5999.txt"),
            request("GET", "/data/length-6000.txt"),
            request("GET", "/data/length-6001.bin"), flags=0x07),
        "seed-imagemap-coordinates": multipacket(
            request("GET", "/shapes.map?10,20"),
            request("GET", "/shapes.map?"),
            request("GET", "/shapes.map?-2147483648,2147483647"),
            request("GET", "/shapes.map?nan,1e309"), flags=0x07),
        "seed-charset-translate": multipacket(
            request("POST", "/charset", (
                "Content-Type: text/plain; charset=UTF-8", "Content-Length: 8"),
                b"fuzz\xc2\xa3\xc3\xa9"),
            request("POST", "/charset", (
                "Transfer-Encoding: chunked", "Content-Type: text/plain; charset=UTF-8"),
                b"1\r\n\xc2\r\n1\r\n\xa3\r\n0\r\n\r\n"),
            request("POST", "/charset", (
                "Transfer-Encoding: chunked", "Content-Type: text/plain; charset=UTF-8"),
                b"1\r\n\xff\r\n0\r\n\r\n"), flags=0x07),
        "seed-tls-backend-proxy": multipacket(
            request("GET", "/tls-backend/index.txt?tls=one", (
                "Connection: keep-alive", "X-Forwarded-Proto: fuzz")),
            request("HEAD", "/tls-backend/index.html", (
                "Range: bytes=0-7", "If-None-Match: \"tls-fuzz\"")),
            request("POST", "/tls-backend/index.txt", (
                "Content-Type: application/octet-stream", "Content-Length: 8"),
                b"tls-fuzz"), flags=0x07),
        "seed-cache-socache-dbm": multipacket(
            request("GET", "/socache/index.txt?key=one", (
                "Cache-Control: max-age=60",)),
            request("GET", "/socache/index.txt?key=one", (
                "Cache-Control: max-age=0", "If-None-Match: \"dbm-fuzz\"")),
            request("HEAD", "/socache/index.txt?key=two", (
                "Range: bytes=0-3",)),
            request("GET", "/socache/index.txt?key=three", (
                "Cache-Control: no-cache, no-store",)), flags=0x07),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", nargs="?", type=Path,
                        default=Path(__file__).resolve().parent / "corpus")
    args = parser.parse_args()
    args.corpus.mkdir(parents=True, exist_ok=True)
    for name, data in corpus_seeds().items():
        (args.corpus / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes")


if __name__ == "__main__":
    main()
