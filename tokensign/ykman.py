"""Lectura opcional del contador de reintentos de PIN de una YubiKey (PIV) vía `ykman piv info`.

`ykman piv info` no consume intentos de PIN (solo consulta el applet PIV).
El parser se probó con salidas de ejemplo; contra una YubiKey real no se midió.
"""

from __future__ import annotations

import re
import subprocess

_RX = re.compile(r"PIN tries remaining:\s*(\d+)(?:\s*/\s*(\d+))?", re.I)


def parse_pin_tries(text: str) -> tuple[int, int | None] | None:
    m = _RX.search(text)
    if not m:
        return None
    return int(m.group(1)), (int(m.group(2)) if m.group(2) else None)


def pin_tries(ykman: str = "ykman", serial: str | None = None) -> tuple[int, int | None] | None:
    cmd = [ykman]
    if serial:
        cmd += ["--device", serial]
    cmd += ["piv", "info"]
    cp = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    if cp.returncode != 0:
        return None
    return parse_pin_tries(cp.stdout)
