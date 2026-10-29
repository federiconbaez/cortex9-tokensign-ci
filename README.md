# cortex9-tokensign-ci

Firma Authenticode de `.exe` para Windows desde Linux con el certificado en un token de
hardware (YubiKey PIV, token EV/OV), con un **preflight que no consume intentos de PIN**:
valida módulo PKCS#11, token, slot, coincidencia certificado↔clave, vigencia y EKU,
cadena intermedia, alcance de la TSA y el contador de reintentos de PIN **antes** de pedir el PIN.

Estado: MVP de un día. La medición está pre-registrada en [`lab/prereg.json`](lab/prereg.json);
los resultados se agregan en el PR siguiente al de este commit.

Licencia: Apache-2.0.
