"""Lectura de un token PKCS#11 SIN iniciar sesión, a través de pkcs11-tool (OpenSC).

Ninguna función de este módulo pasa --login ni --pin: solo se leen slots,
flags del token y objetos públicos (certificado y clave pública).
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field

PKCS11_TOOL = os.environ.get("TOKENSIGN_PKCS11_TOOL", "pkcs11-tool")

FORBIDDEN_ARGS = ("--login", "-l", "--pin", "-p", "--so-pin", "--login-type")


class P11Error(Exception):
    pass


@dataclass
class Token:
    slot: str
    label: str = ""
    serial: str = ""
    flags: list[str] = field(default_factory=list)
    uninitialized: bool = False

    @property
    def pin_final_try(self) -> bool:
        return "final user PIN try" in self.flags

    @property
    def pin_locked(self) -> bool:
        return "user PIN locked" in self.flags

    @property
    def pin_count_low(self) -> bool:
        return "user PIN count low" in self.flags


def _run(module: str, args: list[str], timeout: float = 20.0) -> subprocess.CompletedProcess:
    for a in args:
        if a in FORBIDDEN_ARGS:
            raise AssertionError(f"argumento prohibido en preflight: {a}")
    cmd = [PKCS11_TOOL, "--module", module, *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def parse_slots(text: str) -> list[Token]:
    """Parsea la salida de `pkcs11-tool -L`."""
    tokens: list[Token] = []
    cur: Token | None = None
    for line in text.splitlines():
        m = re.match(r"^Slot (\d+) \((0x[0-9a-fA-F]+)\)", line)
        if m:
            cur = Token(slot=m.group(2))
            tokens.append(cur)
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith("token state:") and "uninitialized" in s:
            cur.uninitialized = True
        elif s.startswith("token label"):
            cur.label = s.split(":", 1)[1].strip()
        elif s.startswith("serial num"):
            cur.serial = s.split(":", 1)[1].strip()
        elif s.startswith("token flags"):
            raw = s.split(":", 1)[1]
            cur.flags = [f.strip() for f in raw.split(",") if f.strip()]
    return [t for t in tokens if not t.uninitialized]


def list_tokens(module: str) -> list[Token]:
    if not os.path.isfile(module):
        raise P11Error(f"no existe el módulo PKCS#11 {module}")
    cp = _run(module, ["-L"])
    if cp.returncode != 0 and "No slots" in (cp.stdout + cp.stderr):
        return []
    if cp.returncode != 0:
        raise P11Error(f"pkcs11-tool no pudo cargar {module}: {(cp.stderr or cp.stdout).strip()}")
    return parse_slots(cp.stdout)


def read_public_object(module: str, token_label: str, obj_type: str, obj_id: str) -> bytes | None:
    """Devuelve el DER del objeto público (cert o pubkey) con ese id, o None."""
    assert obj_type in ("cert", "pubkey")
    with tempfile.TemporaryDirectory(dir=os.environ.get("TOKENSIGN_WORKDIR")) as d:
        out = os.path.join(d, "obj.der")
        cp = _run(module, ["--token-label", token_label, "--read-object", "--type", obj_type,
                           "--id", obj_id, "--output-file", out])
        if cp.returncode != 0 or not os.path.exists(out):
            return None
        with open(out, "rb") as fh:
            data = fh.read()
        return data or None
