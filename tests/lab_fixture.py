"""Laboratorio compartido por los tests de integración (SoftHSM2 + TSA local).

Si falta softhsm2, osslsigncode u opensc, los tests FALLAN (no se saltean).
"""

import os
import shutil
import tempfile

from lab import pki as pkimod
from lab import tokens, tsa_server

_STATE = {}


def lab():
    if _STATE:
        return _STATE
    for tool in ("softhsm2-util", "pkcs11-tool", "osslsigncode", "openssl"):
        if shutil.which(tool) is None:
            raise RuntimeError(f"falta {tool}: instalar softhsm2 opensc osslsigncode")
    base = os.environ.get("TOKENSIGN_TEST_DIR") or os.path.join(os.getcwd(), ".lab", "tests")
    os.makedirs(base, exist_ok=True)
    wd = tempfile.mkdtemp(prefix="t-", dir=base)
    os.environ["TOKENSIGN_WORKDIR"] = wd
    pki = pkimod.build(os.path.join(wd, "pki"))
    tk = tokens.setup(wd, pki)
    srv, url = tsa_server.start(os.path.join(wd, "tsa"), pki)
    _STATE.update(wd=wd, pki=pki, tk=tk, srv=srv, tsa_url=url)
    return _STATE
