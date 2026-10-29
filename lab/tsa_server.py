"""TSA RFC 3161 local para el laboratorio: responde con `openssl ts -reply`."""

from __future__ import annotations

import os
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TS_CNF = """\
[ tsa ]
default_tsa = tsa_config1
[ tsa_config1 ]
serial = {serial}
crypto_device = builtin
signer_digest = sha256
default_policy = 1.3.6.1.4.1.99999.1.1
digests = sha256, sha384, sha512, sha1
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
"""


def start(workdir: str, pki: dict[str, str], port: int = 0):
    os.makedirs(workdir, exist_ok=True)
    cnf = os.path.join(workdir, "ts.cnf")
    serial = os.path.join(workdir, "tsaserial")
    with open(serial, "w") as fh:
        fh.write("01\n")
    with open(cnf, "w") as fh:
        fh.write(TS_CNF.format(serial=serial))
    lock = threading.Lock()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silencioso
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            q = self.rfile.read(n)
            with lock, tempfile.TemporaryDirectory(dir=workdir) as d:
                qf, rf = os.path.join(d, "q.tsq"), os.path.join(d, "r.tsr")
                with open(qf, "wb") as fh:
                    fh.write(q)
                cp = subprocess.run(["openssl", "ts", "-reply", "-config", cnf, "-queryfile", qf,
                                     "-inkey", pki["tsa_key"], "-signer", pki["tsa_cert"],
                                     "-chain", pki["chain_full"], "-out", rf],
                                    capture_output=True)
                if cp.returncode != 0 or not os.path.exists(rf):
                    self.send_response(500)
                    self.end_headers()
                    return
                with open(rf, "rb") as fh:
                    body = fh.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"
