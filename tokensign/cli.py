"""CLI: tokensign preflight | sign | verify."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

from . import preflight, sign as signmod


def _pf_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--module", required=True, help="ruta al módulo PKCS#11 (ykcs11, libsofthsm2, ...)")
    p.add_argument("--token-label", required=True)
    p.add_argument("--key-id", required=True, help="id hex del objeto (p. ej. 01; en ykcs11 el slot 9a es 01)")
    p.add_argument("--cert", help="certificado de firma (PEM/DER); si falta, se lee del token")
    p.add_argument("--chain", help="bundle PEM con intermedias y raíz")
    p.add_argument("--tsa", help="URL de la TSA RFC 3161")
    p.add_argument("--ykman", help="ruta a ykman para leer 'PIN tries remaining' (opcional)")
    p.add_argument("--min-pin-tries", type=int, default=2)
    p.add_argument("--json", action="store_true")


def _cfg(a) -> preflight.Config:
    return preflight.Config(module=a.module, token_label=a.token_label, key_id=a.key_id,
                            cert_path=a.cert, chain_path=a.chain, tsa_url=a.tsa, ykman=a.ykman,
                            min_pin_tries=a.min_pin_tries)


def _print(rep: preflight.Report, as_json: bool) -> None:
    if as_json:
        print(json.dumps({"ok": rep.ok, "findings": [f.__dict__ for f in rep.findings]},
                         ensure_ascii=False, indent=2))
        return
    for f in rep.findings:
        mark = {"ok": "OK  ", "warning": "WARN", "error": "FAIL"}[f.severity]
        print(f"[{mark}] {f.code}: {f.detail}")
    print("preflight:", "OK, se puede pedir el PIN" if rep.ok else "FALLA, no se pide el PIN")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tokensign")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p1 = sub.add_parser("preflight", help="valida token, cadena y TSA sin pedir PIN")
    _pf_args(p1)
    p2 = sub.add_parser("sign", help="preflight y, si pasa, firma con osslsigncode")
    _pf_args(p2)
    p2.add_argument("--in", dest="infile", required=True)
    p2.add_argument("--out", dest="outfile", required=True)
    p2.add_argument("--desc", default="tokensign")
    p3 = sub.add_parser("verify", help="osslsigncode verify contra una raíz dada")
    p3.add_argument("--in", dest="infile", required=True)
    p3.add_argument("--ca", required=True)
    p3.add_argument("--tsa-ca")
    a = ap.parse_args(argv)

    if a.cmd == "verify":
        cp = signmod.verify(a.infile, a.ca, a.tsa_ca)
        sys.stdout.write(cp.stdout)
        sys.stderr.write(cp.stderr)
        return cp.returncode

    rep = preflight.run(_cfg(a))
    _print(rep, a.json)
    if not rep.ok:
        return 2
    if a.cmd == "preflight":
        return 0
    pin = os.environ.get("TOKENSIGN_PIN") or getpass.getpass("PIN del token: ")
    cp = signmod.sign(a.module, a.token_label, a.key_id, pin, a.infile, a.outfile,
                      a.chain, a.tsa, a.desc)
    sys.stdout.write(cp.stdout)
    sys.stderr.write(cp.stderr)
    return cp.returncode


if __name__ == "__main__":
    sys.exit(main())
