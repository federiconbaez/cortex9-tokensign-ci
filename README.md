# cortex9-tokensign-ci

Firma Authenticode de `.exe` para Windows desde Linux con el certificado en un token de
hardware (YubiKey PIV, token EV/OV) **y un preflight que no consume intentos de PIN**.

Firmar desde Linux con un token falla por detalles: cadena intermedia que falta, slot
equivocado, módulo PKCS#11 equivocado, certificado vencido, TSA caída. Cada intento con un
PIN tipeado acerca la llave al bloqueo (en PIV, 3 intentos). `tokensign preflight` revisa
todo eso **antes** de pedir el PIN, y `tokensign sign` solo pide el PIN si el preflight pasó.

Estado: **MVP de un día**. Licencia Apache-2.0.

## Qué revisa el preflight (sin `C_Login`)

| Código | Qué detecta | Cómo |
|---|---|---|
| `module.load_failed`, `module.token_absent` | módulo inexistente, o módulo que no expone el token pedido | `pkcs11-tool -L` |
| `pin.final_try`, `pin.locked` (error), `pin.count_low` (aviso) | flags `CKF_USER_PIN_FINAL_TRY` / `LOCKED` / `COUNT_LOW` del token; opcional `ykman piv info` (`--ykman`) | flags del token, sin login |
| `slot.key_absent` | no hay clave pública ni certificado con ese id en el token | objetos públicos |
| `slot.cert_key_mismatch` | la clave pública del slot no es la del certificado | comparación de SPKI |
| `cert.expired`, `cert.not_yet_valid`, `cert.no_codesigning_eku` | certificado de firma inutilizable | `cryptography` |
| `chain.incomplete`, `chain.expired_ca`, `chain.missing` | falta un eslabón hasta una raíz autofirmada | verificación de firmas de la cadena |
| `tsa.unreachable` | la TSA no responde un `TimeStampReq` RFC 3161 real con status 0/1 | consulta HTTP con timeout |

El PIN nunca se pasa por argv: `tokensign sign` lo lee de `TOKENSIGN_PIN` o de la terminal
y se lo da a `osslsigncode` con `-readpass` desde un archivo `0600` en un directorio privado.

```sh
pip install .
tokensign preflight --module /usr/lib/x86_64-linux-gnu/libykcs11.so --token-label "YubiKey PIV #12345678" \
  --key-id 01 --chain chain.pem --tsa http://timestamp.digicert.com --ykman ykman
tokensign sign  ...mismos argumentos...  --in app.exe --out app-signed.exe
tokensign verify --in app-signed.exe --ca root.pem
```

## Resultados (medidos)

Pre-registro: [`lab/prereg.json`](lab/prereg.json), commit `57c938c`, empujado a GitHub antes
de la medición oficial. Comando: `python -m lab.measure`.

Laboratorio: PKI de prueba generada en cada corrida (raíz RSA-3072, intermedia, hoja de firma
RSA-3072, hoja EC P-256, TSA), dos tokens **SoftHSM2** (`cx9-rsa`, `cx9-ec`), TSA local con
`openssl ts -reply`. Cada corrida de preflight pasa por `pkcs11-spy` (OpenSC), que registra
todas las llamadas PKCS#11; se cuentan las `C_Login`.

| Métrica | Umbral | Box (Debian 13, osslsigncode 2.9) | CI run [40883389471](https://github.com/federiconbaez/cortex9-tokensign-ci/actions/runs/40883389471) |
|---|---|---|---|
| Fallas inyectadas detectadas con el código esperado | 6/6 | **6/6** | **6/6** (ubuntu-24.04, osslsigncode 2.8) |
| Controles sanos sin errores (falsos positivos) | 2/2 | **2/2** | **2/2** |
| `C_Login` durante las 8 corridas de preflight | 0 | **0** | **0** |
| Control del contador: `C_Login` en una firma real vía el mismo spy | ≥ 1 | 1 | ≥ 1 (el job falla si no) |
| `osslsigncode verify` de 50 PE firmados (25 RSA, 25 EC, con timestamp) | 50/50 | **50/50** | **50/50** |
| `signtool verify /pa` en `windows-latest` (Windows Server 2025, raíz del lab importada en `LocalMachine\Root`) | 50/50 | no aplica | **50/50**; con timestamp 50/50; `Get-AuthenticodeSignature` Valid 50/50; los 50 se ejecutaron |

Las 6 fallas: cadena sin intermedia, id de slot equivocado (02 en vez de 01), certificado
vencido para la misma clave, TSA en un puerto cerrado, módulo equivocado (`opensc-pkcs11.so`
sin lector), y último intento de PIN (`CKF_USER_PIN_FINAL_TRY` inyectado).

**Caveat "por construcción":** 6/6 y 0 falsos positivos son sobre un corpus que escribió el
mismo autor que la herramienta, y el laboratorio se usó durante el desarrollo. El pre-registro
fija ese corpus, no es una prueba ciega. Mide que cada chequeo funciona contra un token PKCS#11
real (SoftHSM2), no la cobertura de fallas del mundo real.

Salida de la corrida en la box: [`results/box-2026-10-29.json`](results/box-2026-10-29.json).

## Alcance: qué NO está verificado

- **No se probó con una YubiKey ni con un token EV real.** Todo es SoftHSM2. En particular:
  - Que `libykcs11` exponga `CKF_USER_PIN_FINAL_TRY`/`LOCKED` según los reintentos PIV: sin verificar.
  - SoftHSM2 nunca bloquea el PIN y solo marca `COUNT_LOW`; el caso de último intento se
    **inyecta** con [`shim/fault_p11.c`](shim/fault_p11.c), que reenvía a SoftHSM2 y suma el flag.
  - `--ykman` (lectura de `PIN tries remaining`) solo está probado con texto de ejemplo.
- Que `pkcs11-tool` sin `--login` no consuma intentos en un token real: lo medimos con SoftHSM2
  vía `pkcs11-spy` (0 `C_Login`), no en hardware.
- Tokens de proveedores (SafeNet eToken, Certum, DigiCert KeyLocker): sin probar.
- MSI: no se firmó ni verificó ningún `.msi` (la idea original decía PE/MSI). Solo PE de 64 bits.
- `signtool /pa` se corrió con una raíz de laboratorio importada a mano, no con una CA pública:
  no dice nada de SmartScreen ni de la reputación de un certificado OV/EV.
- El preflight usa la salida de texto de `pkcs11-tool` (OpenSC 0.25/0.26); otro formato puede romper el parser.
- La TSA solo se probó local; TSAs públicas (DigiCert, Sectigo) no se consultaron en la medición.

## Tests

`python -m tests.run`: 28 tests (unitarios + integración contra SoftHSM2, osslsigncode y la
TSA local). Si falta una dependencia el test falla; un test salteado hace fallar el job.

## Tamaño honesto

Esto es el núcleo de un día. Producto completo estimado en 2 semanas de una persona (prueba
con YubiKey 5 y tokens EV reales, MSI, varias llaves, paquete para CI).
