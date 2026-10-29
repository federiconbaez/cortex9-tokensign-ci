/*
 * fault_p11: módulo PKCS#11 de inyección de fallas para el laboratorio.
 *
 * Reenvía todas las llamadas al módulo real indicado en FAULT_P11_TARGET
 * (por ejemplo libsofthsm2.so) y solo modifica C_GetTokenInfo: suma a
 * `flags` los bits pedidos en FAULT_P11_TOKEN_FLAGS (hex). Sirve para
 * simular un token con CKF_USER_PIN_FINAL_TRY o CKF_USER_PIN_LOCKED, que
 * SoftHSM no produce nunca. No es un token real: es una falla inyectada.
 *
 * Además cuenta las llamadas a C_Login en FAULT_P11_LOGIN_LOG (una línea
 * por llamada), como segundo contador independiente de pkcs11-spy.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <p11-kit/pkcs11.h>

static CK_FUNCTION_LIST *real;
static CK_FUNCTION_LIST mine;

static CK_RV fault_get_token_info(CK_SLOT_ID slot, CK_TOKEN_INFO *info)
{
    CK_RV rv = real->C_GetTokenInfo(slot, info);
    const char *f = getenv("FAULT_P11_TOKEN_FLAGS");
    if (rv == CKR_OK && info && f && *f)
        info->flags |= (CK_FLAGS)strtoul(f, NULL, 16);
    return rv;
}

static CK_RV fault_login(CK_SESSION_HANDLE s, CK_USER_TYPE u,
                         unsigned char *pin, unsigned long len)
{
    const char *path = getenv("FAULT_P11_LOGIN_LOG");
    if (path && *path) {
        FILE *fp = fopen(path, "a");
        if (fp) { fprintf(fp, "C_Login user_type=%lu\n", (unsigned long)u); fclose(fp); }
    }
    return real->C_Login(s, u, pin, len);
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST **out)
{
    if (!out) return CKR_ARGUMENTS_BAD;
    if (!real) {
        const char *target = getenv("FAULT_P11_TARGET");
        if (!target || !*target) return CKR_GENERAL_ERROR;
        void *h = dlopen(target, RTLD_NOW | RTLD_LOCAL);
        if (!h) return CKR_GENERAL_ERROR;
        CK_RV (*gfl)(CK_FUNCTION_LIST **) =
            (CK_RV (*)(CK_FUNCTION_LIST **))dlsym(h, "C_GetFunctionList");
        if (!gfl) return CKR_GENERAL_ERROR;
        CK_RV rv = gfl(&real);
        if (rv != CKR_OK) return rv;
        memcpy(&mine, real, sizeof mine);
        mine.C_GetFunctionList = C_GetFunctionList;
        mine.C_GetTokenInfo = fault_get_token_info;
        mine.C_Login = fault_login;
    }
    *out = &mine;
    return CKR_OK;
}
