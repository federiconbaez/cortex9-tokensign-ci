"""Preflight: valida todo lo que puede fallar en una firma con token ANTES de pedir el PIN.

Invariante: nada en este módulo inicia sesión en el token (C_Login) ni recibe un PIN.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography import x509

from . import chain as chainmod
from . import p11, tsa
from . import ykman as ykmod


@dataclass
class Finding:
    code: str
    severity: str  # "error" | "warning" | "ok"
    detail: str


@dataclass
class Config:
    module: str
    token_label: str
    key_id: str
    cert_path: str | None = None
    chain_path: str | None = None
    tsa_url: str | None = None
    tsa_timeout: float = 5.0
    ykman: str | None = None  # ruta a ykman para leer reintentos de PIN (opcional)
    min_pin_tries: int = 2


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)

    def add(self, code: str, severity: str, detail: str) -> None:
        self.findings.append(Finding(code, severity, detail))

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "error"]

    @property
    def ok(self) -> bool:
        return not self.errors

    def codes(self) -> list[str]:
        return [f.code for f in self.errors]


def run(cfg: Config) -> Report:
    rep = Report()

    # 1. módulo PKCS#11
    try:
        tokens = p11.list_tokens(cfg.module)
    except p11.P11Error as e:
        rep.add("module.load_failed", "error", str(e))
        _offline_checks(cfg, rep, token_cert_der=None)
        return rep
    rep.add("module.loaded", "ok", f"{cfg.module}: {len(tokens)} token(s)")

    # 2. token
    tok = next((t for t in tokens if t.label == cfg.token_label), None)
    if tok is None:
        labels = ", ".join(repr(t.label) for t in tokens) or "ninguno"
        rep.add("module.token_absent", "error",
                f"el módulo no expone un token '{cfg.token_label}' (tokens visibles: {labels}); "
                "¿módulo equivocado (p. ej. opensc-pkcs11 en vez de ykcs11/libsofthsm2)?")
        _offline_checks(cfg, rep, token_cert_der=None)
        return rep

    # 3. reintentos de PIN (flags PKCS#11 y, si se pidió, ykman)
    if tok.pin_locked:
        rep.add("pin.locked", "error", "el token reporta PIN bloqueado (CKF_USER_PIN_LOCKED)")
    elif tok.pin_final_try:
        rep.add("pin.final_try", "error",
                "queda 1 intento de PIN (CKF_USER_PIN_FINAL_TRY): no se pide el PIN")
    elif tok.pin_count_low:
        rep.add("pin.count_low", "warning",
                "hubo al menos un PIN incorrecto desde el último login correcto (CKF_USER_PIN_COUNT_LOW)")
    if cfg.ykman:
        tries = ykmod.pin_tries(cfg.ykman)
        if tries is None:
            rep.add("pin.ykman_unreadable", "error", "no se pudo leer 'PIN tries remaining' con ykman")
        elif tries[0] < cfg.min_pin_tries:
            rep.add("pin.final_try", "error",
                    f"ykman: quedan {tries[0]} intento(s) de PIN (< {cfg.min_pin_tries})")

    # 4. objetos públicos en el slot pedido
    pub_der = p11.read_public_object(cfg.module, cfg.token_label, "pubkey", cfg.key_id)
    tok_cert_der = p11.read_public_object(cfg.module, cfg.token_label, "cert", cfg.key_id)
    if pub_der is None and tok_cert_der is None:
        rep.add("slot.key_absent", "error",
                f"no hay clave pública ni certificado con id {cfg.key_id} en '{cfg.token_label}' "
                "(¿slot/id equivocado?)")
    _offline_checks(cfg, rep, token_cert_der=tok_cert_der, token_pub_der=pub_der)
    return rep


def _load_cert(cfg: Config, token_cert_der: bytes | None) -> x509.Certificate | None:
    if cfg.cert_path:
        with open(cfg.cert_path, "rb") as fh:
            data = fh.read()
        return x509.load_pem_x509_certificate(data) if b"-----BEGIN" in data else x509.load_der_x509_certificate(data)
    if token_cert_der:
        return x509.load_der_x509_certificate(token_cert_der)
    return None


def _offline_checks(cfg: Config, rep: Report, token_cert_der: bytes | None,
                    token_pub_der: bytes | None = None) -> None:
    cert = _load_cert(cfg, token_cert_der)
    if cert is None:
        rep.add("cert.missing", "error", "sin certificado (ni --cert ni en el token)")
    else:
        rep.add("cert.kind", "ok", chainmod.key_kind(cert))
        for code, detail in chainmod.check_leaf(cert):
            rep.add(code, "error", detail)
        # coincidencia cert <-> clave del slot
        spki = chainmod.spki_der(cert)
        if token_pub_der is not None:
            from cryptography.hazmat.primitives.serialization import load_der_public_key
            try:
                tok_spki = chainmod.spki_der(load_der_public_key(token_pub_der))
            except ValueError:
                tok_spki = None
            if tok_spki is not None and tok_spki != spki:
                rep.add("slot.cert_key_mismatch", "error",
                        "la clave pública del slot no coincide con el certificado")
        if cfg.chain_path:
            with open(cfg.chain_path, "rb") as fh:
                bundle = chainmod.load_pem_bundle(fh.read())
            res = chainmod.build_chain(cert, bundle)
            if res.ok:
                rep.add("chain.ok", "ok", " -> ".join(res.path))
            else:
                rep.add(res.code, "error", res.detail)
        else:
            rep.add("chain.missing", "error", "sin --chain: Windows necesita la cadena intermedia")
    if cfg.tsa_url:
        ok, detail = tsa.check_tsa(cfg.tsa_url, cfg.tsa_timeout)
        rep.add("tsa.ok" if ok else "tsa.unreachable", "ok" if ok else "error", detail)
