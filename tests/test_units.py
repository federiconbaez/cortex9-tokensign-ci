import os
import subprocess
import unittest
from unittest import mock

from tokensign import p11, tsa, ykman

LIST_FINAL = """Available slots:
Slot 0 (0x5cb0775f): SoftHSM slot ID 0x5cb0775f
  token label        : cx9-ec
  token manufacturer : SoftHSM project
  token flags        : login required, rng, token initialized, final user PIN try, PIN initialized, other flags=0x20
  serial num         : a4c3c2615cb0775f
Slot 1 (0x1): SoftHSM slot ID 0x1
  token state:   uninitialized
"""

LIST_LOCKED = LIST_FINAL.replace("final user PIN try", "user PIN locked")
LIST_LOW = LIST_FINAL.replace("final user PIN try", "user PIN count low")


class SlotParse(unittest.TestCase):
    def test_final_try(self):
        toks = p11.parse_slots(LIST_FINAL)
        self.assertEqual(len(toks), 1)
        t = toks[0]
        self.assertEqual((t.label, t.serial), ("cx9-ec", "a4c3c2615cb0775f"))
        self.assertTrue(t.pin_final_try)
        self.assertFalse(t.pin_locked)

    def test_locked_and_low(self):
        self.assertTrue(p11.parse_slots(LIST_LOCKED)[0].pin_locked)
        low = p11.parse_slots(LIST_LOW)[0]
        self.assertTrue(low.pin_count_low)
        self.assertFalse(low.pin_final_try)

    def test_uninitialized_dropped(self):
        self.assertEqual([t.label for t in p11.parse_slots(LIST_FINAL)], ["cx9-ec"])

    def test_login_args_forbidden(self):
        for bad in ("--login", "-l", "--pin", "-p", "--so-pin"):
            with self.assertRaises(AssertionError):
                p11._run("/nonexistent.so", ["-O", bad])

    def test_missing_module(self):
        with self.assertRaises(p11.P11Error):
            p11.list_tokens("/nonexistent/libnada.so")


class YkmanParse(unittest.TestCase):
    def test_tries(self):
        txt = "PIV version:              5.4.3\nPIN tries remaining:      1/3\nPUK tries remaining: 3/3\n"
        self.assertEqual(ykman.parse_pin_tries(txt), (1, 3))

    def test_tries_no_total(self):
        self.assertEqual(ykman.parse_pin_tries("PIN tries remaining: 2"), (2, None))

    def test_absent(self):
        self.assertIsNone(ykman.parse_pin_tries("WARNING: no device"))


class TsaQuery(unittest.TestCase):
    def test_query_is_valid_for_openssl(self):
        q = tsa.build_query(b"hola", 0x1234567890)
        d = os.path.join(os.getcwd(), ".lab")
        os.makedirs(d, exist_ok=True)
        f = os.path.join(d, "unit.tsq")
        with open(f, "wb") as fh:
            fh.write(q)
        cp = subprocess.run(["openssl", "ts", "-query", "-in", f, "-text"], capture_output=True, text=True)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("sha256", cp.stdout)
        self.assertIn("Certificate required: yes", cp.stdout)
        self.assertIn("Nonce: 0x1234567890", cp.stdout)

    def test_parse_status(self):
        # TimeStampResp { PKIStatusInfo { status 2 (rejection) } }
        resp = bytes.fromhex("3005" "3003" "020102")
        self.assertEqual(tsa.parse_status(resp), 2)

    def test_parse_garbage(self):
        with self.assertRaises(ValueError):
            tsa.parse_status(b"\x04\x01\x00")

    def test_closed_port(self):
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        ok, detail = tsa.check_tsa(f"http://127.0.0.1:{port}/", timeout=2)
        self.assertFalse(ok)
        self.assertIn("inalcanzable", detail)

    def test_wrong_content_type(self):
        fake = mock.MagicMock()
        fake.__enter__.return_value.read.return_value = b"<html>"
        fake.__enter__.return_value.headers = {"Content-Type": "text/html"}
        with mock.patch("urllib.request.urlopen", return_value=fake):
            ok, detail = tsa.check_tsa("http://example.invalid/")
        self.assertFalse(ok)
        self.assertIn("Content-Type", detail)
