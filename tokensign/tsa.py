"""Chequeo de alcance de una TSA RFC 3161 con una consulta real (sin firmar nada)."""

from __future__ import annotations

import hashlib
import os
import urllib.error
import urllib.request


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


SHA256_ALGID = _tlv(0x30, _tlv(0x06, bytes.fromhex("608648016503040201")) + b"\x05\x00")


def build_query(data: bytes, nonce: int, cert_req: bool = True) -> bytes:
    """TimeStampReq DER (RFC 3161 §2.4.1) con SHA-256."""
    imprint = _tlv(0x30, SHA256_ALGID + _tlv(0x04, hashlib.sha256(data).digest()))
    nb = nonce.to_bytes((nonce.bit_length() + 8) // 8, "big")
    body = _tlv(0x02, b"\x01") + imprint + _tlv(0x02, nb)
    if cert_req:
        body += _tlv(0x01, b"\xff")
    return _tlv(0x30, body)


def parse_status(resp: bytes) -> int:
    """Devuelve PKIStatus del TimeStampResp (0 granted, 1 grantedWithMods, >=2 error)."""
    # TimeStampResp ::= SEQUENCE { status PKIStatusInfo, ... }
    # PKIStatusInfo ::= SEQUENCE { status INTEGER, ... }
    def read(buf: bytes, i: int):
        tag = buf[i]
        ln = buf[i + 1]
        i += 2
        if ln & 0x80:
            k = ln & 0x7F
            ln = int.from_bytes(buf[i:i + k], "big")
            i += k
        return tag, i, ln

    tag, i, _ = read(resp, 0)
    if tag != 0x30:
        raise ValueError("respuesta TSA no es SEQUENCE")
    tag, j, _ = read(resp, i)
    if tag != 0x30:
        raise ValueError("PKIStatusInfo ausente")
    tag, k, ln = read(resp, j)
    if tag != 0x02:
        raise ValueError("status ausente")
    return int.from_bytes(resp[k:k + ln], "big")


def check_tsa(url: str, timeout: float = 5.0) -> tuple[bool, str]:
    q = build_query(b"tokensign preflight", int.from_bytes(os.urandom(8), "big"))
    req = urllib.request.Request(url, data=q, method="POST",
                                 headers={"Content-Type": "application/timestamp-query"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
            ctype = r.headers.get("Content-Type", "")
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return False, f"TSA inalcanzable: {e}"
    if "timestamp-reply" not in ctype:
        return False, f"Content-Type inesperado: {ctype!r}"
    try:
        st = parse_status(body)
    except (ValueError, IndexError) as e:
        return False, f"respuesta TSA ilegible: {e}"
    if st not in (0, 1):
        return False, f"TSA respondió status {st}"
    return True, f"TSA respondió status {st}"
