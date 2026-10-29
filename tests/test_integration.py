"""Integración contra SoftHSM2 real, osslsigncode real y una TSA RFC 3161 local."""

import datetime as dt
import os
import subprocess
import unittest
from unittest import mock

from cryptography import x509

from tests.lab_fixture import lab
from tokensign import chain, cli, preflight, sign


def cfg(L, **kw):
    base = dict(module=L["tk"]["module"], token_label="cx9-ec", key_id="01",
                chain_path=L["pki"]["chain_full"], tsa_url=L["tsa_url"])
    base.update(kw)
    return preflight.Config(**base)


class Preflight(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.L = lab()

    def test_healthy_rsa_and_ec(self):
        for label, kind in (("cx9-rsa", "RSA-3072"), ("cx9-ec", "EC-secp256r1")):
            rep = preflight.run(cfg(self.L, token_label=label))
            self.assertTrue(rep.ok, rep.codes())
            kinds = [f.detail for f in rep.findings if f.code == "cert.kind"]
            self.assertEqual(kinds, [kind])

    def test_chain_incomplete(self):
        rep = preflight.run(cfg(self.L, chain_path=self.L["pki"]["chain_no_inter"]))
        self.assertIn("chain.incomplete", rep.codes())

    def test_wrong_key_id(self):
        rep = preflight.run(cfg(self.L, key_id="02"))
        self.assertIn("slot.key_absent", rep.codes())

    def test_cert_key_mismatch(self):
        rep = preflight.run(cfg(self.L, token_label="cx9-rsa", cert_path=self.L["pki"]["ec_cert"]))
        self.assertIn("slot.cert_key_mismatch", rep.codes())

    def test_expired(self):
        rep = preflight.run(cfg(self.L, cert_path=self.L["pki"]["ec_cert_expired"]))
        self.assertEqual(rep.codes(), ["cert.expired"])

    def test_unknown_token(self):
        rep = preflight.run(cfg(self.L, token_label="no-existe"))
        self.assertIn("module.token_absent", rep.codes())

    def test_missing_chain_is_error(self):
        rep = preflight.run(cfg(self.L, chain_path=None))
        self.assertIn("chain.missing", rep.codes())

    def test_no_login_in_any_pkcs11_tool_call(self):
        real = subprocess.run
        seen = []

        def spy(cmd, *a, **k):
            seen.append(list(cmd))
            return real(cmd, *a, **k)

        with mock.patch("tokensign.p11.subprocess.run", side_effect=spy):
            preflight.run(cfg(self.L))
        self.assertGreaterEqual(len(seen), 3)
        for cmd in seen:
            self.assertNotIn("--login", cmd)
            self.assertNotIn("--pin", cmd)
            self.assertNotIn(self.L["tk"]["pin"], cmd)

    def test_tbs_expiry_logic(self):
        c = x509.load_pem_x509_certificate(open(self.L["pki"]["ec_cert"], "rb").read())
        future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=4000)
        codes = [code for code, _ in chain.check_leaf(c, now=future)]
        self.assertEqual(codes, ["cert.expired"])


class SignVerify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.L = lab()
        wd = cls.L["wd"]
        src = os.path.join(wd, "t.c")
        open(src, "w").write('#include <stdio.h>\nint main(void){puts("t");return 0;}\n')
        cls.exe = os.path.join(wd, "t.exe")
        subprocess.run(["x86_64-w64-mingw32-gcc", "-O2", "-s", "-o", cls.exe, src], check=True)

    def _sign(self, label, out):
        return sign.sign(self.L["tk"]["module"], label, "01", self.L["tk"]["pin"], self.exe, out,
                         self.L["pki"]["chain_full"], self.L["tsa_url"])

    def test_sign_verify_rsa_ec(self):
        for label in ("cx9-rsa", "cx9-ec"):
            out = os.path.join(self.L["wd"], f"t-{label}.exe")
            cp = self._sign(label, out)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            vp = sign.verify(out, self.L["pki"]["root"], self.L["pki"]["root"])
            self.assertEqual(vp.returncode, 0, vp.stdout + vp.stderr)
            self.assertIn("Signature verification: ok", vp.stdout)
            self.assertIn("Timestamp", vp.stdout)

    def test_tampered_fails_verify(self):
        out = os.path.join(self.L["wd"], "t-tamper.exe")
        self.assertEqual(self._sign("cx9-ec", out).returncode, 0)
        data = bytearray(open(out, "rb").read())
        data[0x400] ^= 0xFF  # dentro de .text, fuera de la firma
        open(out, "wb").write(bytes(data))
        vp = sign.verify(out, self.L["pki"]["root"], self.L["pki"]["root"])
        self.assertNotEqual(vp.returncode, 0)

    def test_wrong_root_fails_verify(self):
        out = os.path.join(self.L["wd"], "t-root.exe")
        self.assertEqual(self._sign("cx9-rsa", out).returncode, 0)
        vp = sign.verify(out, self.L["pki"]["tsa_cert"])
        self.assertNotEqual(vp.returncode, 0)

    def test_pin_not_in_argv(self):
        real = subprocess.run
        seen = []

        def spy(cmd, *a, **k):
            seen.append(list(cmd))
            return real(cmd, *a, **k)

        with mock.patch("tokensign.sign.subprocess.run", side_effect=spy):
            self._sign("cx9-ec", os.path.join(self.L["wd"], "t-argv.exe"))
        seen = [c for c in seen if c and c[0].endswith("osslsigncode")]
        self.assertEqual(len(seen), 1)
        self.assertNotIn(self.L["tk"]["pin"], " ".join(seen[0]))
        self.assertIn("-readpass", seen[0])

    def test_cli_blocks_before_pin(self):
        out = os.path.join(self.L["wd"], "t-cli.exe")
        with mock.patch("getpass.getpass", side_effect=AssertionError("pidió PIN")):
            rc = cli.main(["sign", "--module", self.L["tk"]["module"], "--token-label", "cx9-ec",
                           "--key-id", "01", "--chain", self.L["pki"]["chain_no_inter"],
                           "--tsa", self.L["tsa_url"], "--in", self.exe, "--out", out])
        self.assertEqual(rc, 2)
        self.assertFalse(os.path.exists(out))

    def test_cli_sign_ok(self):
        out = os.path.join(self.L["wd"], "t-cli-ok.exe")
        with mock.patch.dict(os.environ, {"TOKENSIGN_PIN": self.L["tk"]["pin"]}):
            rc = cli.main(["sign", "--module", self.L["tk"]["module"], "--token-label", "cx9-rsa",
                           "--key-id", "01", "--chain", self.L["pki"]["chain_full"],
                           "--tsa", self.L["tsa_url"], "--in", self.exe, "--out", out])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(out))
