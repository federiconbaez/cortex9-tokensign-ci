"""Validación de certificado de firma y cadena, sin red."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID


@dataclass
class ChainResult:
    ok: bool
    code: str
    detail: str
    path: list[str]


def load_pem_bundle(data: bytes) -> list[x509.Certificate]:
    return x509.load_pem_x509_certificates(data)


def _verify_sig(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    pub = issuer.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(),
                       child.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       ec.ECDSA(child.signature_hash_algorithm))
        else:
            return False
        return True
    except InvalidSignature:
        return False


def _self_signed(c: x509.Certificate) -> bool:
    return c.issuer == c.subject and _verify_sig(c, c)


def check_leaf(cert: x509.Certificate, now: dt.datetime | None = None) -> list[tuple[str, str]]:
    """Errores (código, detalle) del certificado de firma en sí."""
    now = now or dt.datetime.now(dt.timezone.utc)
    errs: list[tuple[str, str]] = []
    if cert.not_valid_after_utc < now:
        errs.append(("cert.expired", f"venció el {cert.not_valid_after_utc.isoformat()}"))
    if cert.not_valid_before_utc > now:
        errs.append(("cert.not_yet_valid", f"válido desde {cert.not_valid_before_utc.isoformat()}"))
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.CODE_SIGNING not in eku:
            errs.append(("cert.no_codesigning_eku", "el EKU no incluye codeSigning"))
    except x509.ExtensionNotFound:
        errs.append(("cert.no_codesigning_eku", "sin extensión EKU"))
    return errs


def build_chain(leaf: x509.Certificate, bundle: list[x509.Certificate],
                now: dt.datetime | None = None) -> ChainResult:
    """Arma la cadena hoja -> raíz usando solo `bundle`. Falla si falta un eslabón."""
    now = now or dt.datetime.now(dt.timezone.utc)
    path = [leaf.subject.rfc4514_string()]
    cur = leaf
    for _ in range(10):
        if _self_signed(cur):
            return ChainResult(True, "ok", "cadena completa hasta raíz autofirmada", path)
        cands = [c for c in bundle if c.subject == cur.issuer and _verify_sig(cur, c)]
        if not cands:
            return ChainResult(False, "chain.incomplete",
                               f"falta el emisor '{cur.issuer.rfc4514_string()}' en la cadena", path)
        nxt = cands[0]
        if nxt.not_valid_after_utc < now:
            return ChainResult(False, "chain.expired_ca",
                               f"CA vencida: {nxt.subject.rfc4514_string()}", path)
        path.append(nxt.subject.rfc4514_string())
        cur = nxt
    return ChainResult(False, "chain.too_long", "más de 10 eslabones", path)


def spki_der(cert_or_key) -> bytes:
    pub = cert_or_key.public_key() if isinstance(cert_or_key, x509.Certificate) else cert_or_key
    return pub.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def key_kind(cert: x509.Certificate) -> str:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA-{pub.key_size}"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC-{pub.curve.name}"
    return type(pub).__name__
