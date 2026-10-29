"""PKI de laboratorio: raíz, intermedia, hojas de firma RSA y EC, hoja vencida y TSA.

Todo se genera en tiempo de ejecución dentro de un directorio de trabajo; ninguna
clave se versiona. Es una PKI de prueba, no confiable fuera del laboratorio.
"""

from __future__ import annotations

import datetime as dt
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

NOW = dt.datetime.now(dt.timezone.utc)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "cortex9 tokensign lab"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject_cn, pub, issuer_cn, issuer_key, *, ca: bool, eku=None, nb=None, na=None,
          eku_critical=False, path_len=None):
    b = (x509.CertificateBuilder()
         .subject_name(_name(subject_cn)).issuer_name(_name(issuer_cn))
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(nb or NOW - dt.timedelta(days=1))
         .not_valid_after(na or NOW + dt.timedelta(days=365))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=path_len), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                            critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                            critical=True)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=eku_critical)
    return b.sign(issuer_key, hashes.SHA256())


def _pem_key(k) -> bytes:
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())


def _der_key(k) -> bytes:
    return k.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())


def _pem(c) -> bytes:
    return c.public_bytes(serialization.Encoding.PEM)


def build(workdir: str) -> dict[str, str]:
    os.makedirs(workdir, exist_ok=True)
    p = lambda n: os.path.join(workdir, n)  # noqa: E731
    root_k = rsa.generate_private_key(65537, 3072)
    root = _cert("tokensign lab root", root_k.public_key(), "tokensign lab root", root_k,
                 ca=True, na=NOW + dt.timedelta(days=3650))
    inter_k = rsa.generate_private_key(65537, 3072)
    inter = _cert("tokensign lab intermediate", inter_k.public_key(), "tokensign lab root", root_k,
                  ca=True, path_len=0, na=NOW + dt.timedelta(days=1825))
    rsa_k = rsa.generate_private_key(65537, 3072)
    leaf_rsa = _cert("tokensign lab codesign RSA", rsa_k.public_key(), "tokensign lab intermediate",
                     inter_k, ca=False, eku=[ExtendedKeyUsageOID.CODE_SIGNING])
    ec_k = ec.generate_private_key(ec.SECP256R1())
    leaf_ec = _cert("tokensign lab codesign EC", ec_k.public_key(), "tokensign lab intermediate",
                    inter_k, ca=False, eku=[ExtendedKeyUsageOID.CODE_SIGNING])
    leaf_ec_expired = _cert("tokensign lab codesign EC", ec_k.public_key(),
                            "tokensign lab intermediate", inter_k, ca=False,
                            eku=[ExtendedKeyUsageOID.CODE_SIGNING],
                            nb=NOW - dt.timedelta(days=400), na=NOW - dt.timedelta(days=35))
    tsa_k = rsa.generate_private_key(65537, 3072)
    tsa = _cert("tokensign lab TSA", tsa_k.public_key(), "tokensign lab intermediate", inter_k,
                ca=False, eku=[ExtendedKeyUsageOID.TIME_STAMPING], eku_critical=True)
    out = {
        "root": p("root.pem"), "inter": p("inter.pem"),
        "chain_full": p("chain-full.pem"), "chain_no_inter": p("chain-no-inter.pem"),
        "rsa_key_der": p("rsa.key.der"), "rsa_cert": p("rsa.pem"),
        "ec_key_der": p("ec.key.der"), "ec_cert": p("ec.pem"), "ec_cert_expired": p("ec-expired.pem"),
        "tsa_key": p("tsa.key"), "tsa_cert": p("tsa.pem"),
    }
    files = {
        "root": _pem(root), "inter": _pem(inter),
        "chain_full": _pem(inter) + _pem(root), "chain_no_inter": _pem(root),
        "rsa_key_der": _der_key(rsa_k), "rsa_cert": _pem(leaf_rsa),
        "ec_key_der": _der_key(ec_k), "ec_cert": _pem(leaf_ec), "ec_cert_expired": _pem(leaf_ec_expired),
        "tsa_key": _pem_key(tsa_k), "tsa_cert": _pem(tsa),
    }
    for k, data in files.items():
        with open(out[k], "wb") as fh:
            fh.write(data)
    for k in ("rsa_cert", "ec_cert"):
        c = x509.load_pem_x509_certificate(files[k])
        der = p(k.replace("_cert", "") + ".cert.der")
        with open(der, "wb") as fh:
            fh.write(c.public_bytes(serialization.Encoding.DER))
        out[k + "_der"] = der
    for k in ("rsa", "ec"):
        key = rsa_k if k == "rsa" else ec_k
        pub = p(f"{k}.pub.der")
        with open(pub, "wb") as fh:
            fh.write(key.public_key().public_bytes(serialization.Encoding.DER,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo))
        out[f"{k}_pub_der"] = pub
    return out
