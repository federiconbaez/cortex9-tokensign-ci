"""Medición pre-registrada (lab/prereg.json). Sale con código != 0 si no se cumple un umbral.

Uso: python -m lab.measure [--workdir DIR] [--out results.json] [--corpus-out DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from lab import pki as pkimod  # noqa: E402
from lab import tokens, tsa_server  # noqa: E402
from tokensign import preflight, sign as signmod  # noqa: E402

LIBDIRS = ["/usr/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu/pkcs11", "/usr/lib"]


def find_lib(name: str) -> str:
    for d in LIBDIRS:
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    raise SystemExit(f"FALLA: no se encontró {name} (instalar opensc)")


def build_shim(workdir: str) -> str:
    out = os.path.join(workdir, "fault_p11.so")
    flags = ["-I/usr/include/p11-kit-1"]
    if shutil.which("pkg-config"):
        inc = subprocess.run(["pkg-config", "--cflags", "p11-kit-1"], capture_output=True, text=True)
        if inc.returncode == 0:
            flags = inc.stdout.split()
    cp = subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIC", *flags, "-shared",
                         "-o", out, os.path.join(ROOT, "shim", "fault_p11.c"), "-ldl"],
                        capture_output=True, text=True)
    if cp.returncode != 0:
        raise SystemExit(f"FALLA: no compila el shim: {cp.stderr}")
    return out


def closed_port_url() -> str:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}/"


def count_logins(log: str) -> int:
    if not os.path.exists(log):
        return 0
    with open(log, errors="replace") as fh:
        return sum(1 for line in fh if "C_Login" in line)


def count_calls(log: str) -> int:
    """Llamadas PKCS#11 registradas por pkcs11-spy (líneas 'N: C_...')."""
    if not os.path.exists(log):
        return 0
    with open(log, errors="replace") as fh:
        return sum(1 for line in fh if re.match(r"^\d+: C_", line))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", default=os.path.join(ROOT, ".lab"))
    ap.add_argument("--out", default=None)
    ap.add_argument("--corpus-out", default=None, help="copia los 50 binarios firmados acá")
    a = ap.parse_args()
    if os.path.exists(a.workdir):
        shutil.rmtree(a.workdir)
    os.makedirs(a.workdir)
    os.environ["TOKENSIGN_WORKDIR"] = a.workdir
    with open(os.path.join(HERE, "prereg.json"), "rb") as fh:
        raw = fh.read()
    prereg = json.loads(raw)

    pki = pkimod.build(os.path.join(a.workdir, "pki"))
    tk = tokens.setup(a.workdir, pki)
    softhsm = tk["module"]
    spy = find_lib("pkcs11-spy.so")
    opensc = find_lib("opensc-pkcs11.so")
    shim = build_shim(a.workdir)
    srv, tsa_url = tsa_server.start(os.path.join(a.workdir, "tsa"), pki)
    down_url = closed_port_url()

    results = {"prereg_sha256": hashlib.sha256(raw).hexdigest(), "cases": [], "signing": {}}
    logdir = os.path.join(a.workdir, "spylogs")
    os.makedirs(logdir)
    total_logins = 0
    for case in prereg["preflight_cases"]:
        target = {"softhsm": softhsm, "opensc": opensc, "shim": shim}[case["module"]]
        log = os.path.join(logdir, case["name"] + ".log")
        env_backup = dict(os.environ)
        os.environ["PKCS11SPY"] = target
        os.environ["PKCS11SPY_OUTPUT"] = log
        if case["module"] == "shim":
            os.environ["FAULT_P11_TARGET"] = softhsm
            os.environ["FAULT_P11_TOKEN_FLAGS"] = case["token_flags"] or ""
            os.environ["FAULT_P11_LOGIN_LOG"] = log + ".shim"
        cfg = preflight.Config(module=spy, token_label=case["token"], key_id=case["key_id"],
                               cert_path=pki[case["cert"]] if case["cert"] else None,
                               chain_path=pki[case["chain"]],
                               tsa_url=tsa_url if case["tsa"] == "up" else down_url)
        t0 = time.monotonic()
        rep = preflight.run(cfg)
        dt_ms = (time.monotonic() - t0) * 1000
        os.environ.clear()
        os.environ.update(env_backup)
        logins = count_logins(log) + count_logins(log + ".shim")
        spy_calls = count_calls(log)
        total_logins += logins
        if case["expect"] == "pass":
            passed = rep.ok
        else:
            exp = case["expect"]
            if exp.endswith(".*"):
                hit = any(c.startswith(exp[:-1]) for c in rep.codes())
            else:
                hit = exp in rep.codes()
            passed = (not rep.ok) and hit
        results["cases"].append({"name": case["name"], "expect": case["expect"], "ok": rep.ok,
                                 "codes": rep.codes(), "passed": passed, "c_login": logins,
                                 "spy_logged_calls": spy_calls, "ms": round(dt_ms, 1)})
        print(f"{case['name']:18s} esperado={case['expect']:20s} errores={rep.codes()} "
              f"C_Login={logins} llamadas_spy={spy_calls} {'OK' if passed else 'NO'}")

    # control positivo del contador: una firma real a través del spy debe registrar C_Login
    hello = os.path.join(a.workdir, "hello.c")
    with open(hello, "w") as fh:
        fh.write('#include <stdio.h>\nint main(void){puts("control");return 0;}\n')
    hexe = os.path.join(a.workdir, "control.exe")
    subprocess.run(["x86_64-w64-mingw32-gcc", "-O2", "-s", "-o", hexe, hello], check=True)
    ctl_log = os.path.join(logdir, "control_sign.log")
    env_backup = dict(os.environ)
    os.environ["PKCS11SPY"] = softhsm
    os.environ["PKCS11SPY_OUTPUT"] = ctl_log
    cp = signmod.sign(spy, "cx9-ec", "01", tk["pin"], hexe, hexe + ".signed", pki["chain_full"], tsa_url)
    os.environ.clear()
    os.environ.update(env_backup)
    ctl_logins = count_logins(ctl_log)
    print(f"control del contador: firma vía spy rc={cp.returncode} C_Login={ctl_logins}")
    results["login_counter_control"] = {"sign_rc": cp.returncode, "c_login": ctl_logins}

    # corpus de 50 binarios
    sc = prereg["sign_corpus"]
    cdir = os.path.join(a.workdir, "corpus")
    os.makedirs(cdir)
    verify_ok = sign_ok = 0
    per = []
    for n in range(sc["count"]):
        src = os.path.join(cdir, f"bin{n:02d}.c")
        with open(src, "w") as fh:
            fh.write(f'#include <stdio.h>\nint main(void){{puts("cortex9 tokensign lab binario {n}");return 0;}}\n')
        exe = os.path.join(cdir, f"bin{n:02d}.exe")
        subprocess.run(["x86_64-w64-mingw32-gcc", "-O2", "-s", "-o", exe, src], check=True)
        token = "cx9-rsa" if n % 2 == 0 else "cx9-ec"
        signed = os.path.join(cdir, f"bin{n:02d}-signed.exe")
        cp = signmod.sign(softhsm, token, "01", tk["pin"], exe, signed, pki["chain_full"], tsa_url,
                          desc=f"cortex9 tokensign lab {n}")
        s_ok = cp.returncode == 0 and os.path.exists(signed)
        v_ok = False
        if s_ok:
            sign_ok += 1
            vp = signmod.verify(signed, pki["root"], pki["root"])
            v_ok = vp.returncode == 0 and "Signature verification: ok" in vp.stdout
            if not v_ok:
                print(vp.stdout[-800:], vp.stderr[-800:])
        else:
            print(cp.stdout[-800:], cp.stderr[-800:])
        verify_ok += int(v_ok)
        per.append({"n": n, "token": token, "signed": s_ok, "verified": v_ok})
    results["signing"] = {"count": sc["count"], "signed": sign_ok, "osslsigncode_verify_ok": verify_ok,
                          "per_binary": per}
    print(f"corpus: firmados {sign_ok}/{sc['count']}, osslsigncode verify OK {verify_ok}/{sc['count']}")
    srv.shutdown()

    if a.corpus_out:
        os.makedirs(a.corpus_out, exist_ok=True)
        for n in range(sc["count"]):
            shutil.copy(os.path.join(cdir, f"bin{n:02d}-signed.exe"), a.corpus_out)
        shutil.copy(pki["root"], os.path.join(a.corpus_out, "lab-root.pem"))

    inj = [c for c in results["cases"] if c["expect"] != "pass"]
    ctl = [c for c in results["cases"] if c["expect"] == "pass"]
    summary = {
        "injected_detected": f"{sum(c['passed'] for c in inj)}/{len(inj)}",
        "controls_pass": f"{sum(c['passed'] for c in ctl)}/{len(ctl)}",
        "c_login_during_preflight": total_logins,
        "login_counter_control_c_login": ctl_logins,
        "osslsigncode_verify": f"{verify_ok}/{sc['count']}",
    }
    results["summary"] = summary
    print(json.dumps(summary, ensure_ascii=False))
    if a.out:
        with open(a.out, "w") as fh:
            json.dump(results, fh, ensure_ascii=False, indent=2)
    fails = []
    if sum(c["passed"] for c in inj) != len(inj):
        fails.append("injected_detected")
    if sum(c["passed"] for c in ctl) != len(ctl):
        fails.append("controls_pass")
    if total_logins != 0:
        fails.append("c_login_during_preflight")
    if ctl_logins < 1:
        fails.append("login_counter_control (contador inválido)")
    if verify_ok != sc["count"]:
        fails.append("osslsigncode_verify")
    if fails:
        print("UMBRAL NO CUMPLIDO:", ", ".join(fails))
        return 1
    print("todos los umbrales de Linux cumplidos")
    return 0


if __name__ == "__main__":
    sys.exit(main())
