#!/usr/bin/env python3
"""TLS client that sends its (real) ClientHello in two TCP segments.

Modern browsers' ClientHello often exceeds one MSS (post-quantum key shares),
so the SNI can land in the second segment. This client reproduces that on
purpose: it cuts the ClientHello just before the server_name extension, sends
the halves as separate segments, then finishes the handshake and an HTTP GET.

usage: split_hello.py <sni> <port> [--whole]
prints the HTTP status code, or 000 on timeout / failure.
"""
import socket, ssl, sys, time

sni, port = sys.argv[1], int(sys.argv[2])
whole = "--whole" in sys.argv

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
tls = ctx.wrap_bio(inc, out, server_hostname=sni)

def pump(sock):
    data = out.read()
    if data:
        sock.sendall(data)

try:
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = out.read()
    if whole:
        s.sendall(hello)
    else:
        name = sni.encode()
        cut = hello.find(name) - 9          # back up over ext type/len, list len, name type/len
        assert cut > 5, "SNI not found in ClientHello"
        s.sendall(hello[:cut])
        time.sleep(0.05)                     # make sure the halves leave as separate segments
        s.sendall(hello[cut:])
    while True:
        try:
            tls.do_handshake()
            break
        except ssl.SSLWantReadError:
            pump(s)
            chunk = s.recv(65536)
            if not chunk:
                raise ConnectionError("closed during handshake")
            inc.write(chunk)
    tls.write(f"GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n".encode())
    pump(s)
    resp = b""
    while b"\r\n" not in resp:
        try:
            resp += tls.read(4096)
        except ssl.SSLWantReadError:
            chunk = s.recv(65536)
            if not chunk:
                break
            inc.write(chunk)
    print(resp.split(b" ")[1].decode() if resp.startswith(b"HTTP/") else "000")
except Exception:
    print("000")
