"""Tokens SoftHSM2 del laboratorio. Usa login SOLO en el armado (nunca en preflight)."""

from __future__ import annotations

import os
import subprocess

SOFTHSM_CANDIDATES = ["/usr/lib/softhsm/libsofthsm2.so",
                      "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"]
SO_PIN = "87654321"
USER_PIN = "123456"


def softhsm_module() -> str:
    for c in SOFTHSM_CANDIDATES:
        if os.path.isfile(c):
            return c
    raise RuntimeError("libsofthsm2.so no encontrado: instalar softhsm2")


def setup(workdir: str, pki: dict[str, str]) -> dict[str, str]:
    tokdir = os.path.join(workdir, "tokens")
    os.makedirs(tokdir, exist_ok=True)
    conf = os.path.join(workdir, "softhsm2.conf")
    with open(conf, "w") as fh:
        fh.write(f"directories.tokendir = {tokdir}\nobjectstore.backend = file\nlog.level = ERROR\n")
    os.environ["SOFTHSM2_CONF"] = conf
    mod = softhsm_module()

    def sh(*args):
        cp = subprocess.run(list(args), capture_output=True, text=True)
        if cp.returncode != 0:
            raise RuntimeError(f"{' '.join(args)}: {cp.stderr or cp.stdout}")
        return cp.stdout

    for label, kind in (("cx9-rsa", "rsa"), ("cx9-ec", "ec")):
        sh("softhsm2-util", "--init-token", "--free", "--label", label,
           "--so-pin", SO_PIN, "--pin", USER_PIN)
        base = ["pkcs11-tool", "--module", mod, "--token-label", label]
        sh(*base, "--login", "--pin", USER_PIN, "--write-object", pki[f"{kind}_key_der"],
           "--type", "privkey", "--id", "01", "--label", f"{kind}-sign", "--usage-sign")
        sh(*base, "--write-object", pki[f"{kind}_pub_der"], "--type", "pubkey", "--id", "01",
           "--label", f"{kind}-sign", "--login", "--pin", USER_PIN)
        sh(*base, "--write-object", pki[f"{kind}_cert_der"], "--type", "cert", "--id", "01",
           "--label", f"{kind}-sign", "--login", "--pin", USER_PIN)
    return {"conf": conf, "module": mod, "pin": USER_PIN}
