"""Firma Authenticode con osslsigncode + motor PKCS#11, y verificación.

El PIN nunca va en la línea de comandos: se escribe en un archivo 0600 dentro de
un directorio temporal privado y se pasa con -readpass.
"""

from __future__ import annotations

import os
import subprocess
import tempfile

OSSLSIGNCODE = os.environ.get("TOKENSIGN_OSSLSIGNCODE", "osslsigncode")


def p11_uri(token_label: str, key_id: str, kind: str) -> str:
    pct = "".join(f"%{key_id[i:i + 2]}" for i in range(0, len(key_id), 2))
    return f"pkcs11:token={token_label};id={pct};type={kind}"


def sign(module: str, token_label: str, key_id: str, pin: str, infile: str, outfile: str,
         chain_path: str | None, tsa_url: str | None, desc: str = "tokensign",
         timeout: float = 120.0) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory(dir=os.environ.get("TOKENSIGN_WORKDIR")) as d:
        os.chmod(d, 0o700)
        pinfile = os.path.join(d, "pin")
        fd = os.open(pinfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(pin)
        cmd = [OSSLSIGNCODE, "sign", "-pkcs11module", module,
               "-pkcs11cert", p11_uri(token_label, key_id, "cert"),
               "-key", p11_uri(token_label, key_id, "private"),
               "-readpass", pinfile, "-h", "sha256", "-n", desc]
        if chain_path:
            cmd += ["-ac", chain_path]
        if tsa_url:
            cmd += ["-ts", tsa_url]
        cmd += ["-in", infile, "-out", outfile]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def verify(infile: str, ca_file: str, tsa_ca_file: str | None = None,
           timeout: float = 60.0) -> subprocess.CompletedProcess:
    cmd = [OSSLSIGNCODE, "verify", "-CAfile", ca_file]
    if tsa_ca_file:
        cmd += ["-TSA-CAfile", tsa_ca_file]
    cmd += ["-in", infile]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
