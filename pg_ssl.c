#include <postgres.h>
#include <fmgr.h>

#include <catalog/pg_type.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <utils/builtins.h>

#define EXTENSION(function) Datum (function)(PG_FUNCTION_ARGS); PG_FUNCTION_INFO_V1(function); Datum (function)(PG_FUNCTION_ARGS)

PG_MODULE_MAGIC;

static inline int B64_write_ASN1(BIO *out, ASN1_VALUE *val, BIO *in, int flags, const ASN1_ITEM *it) {
    BIO *b64;
    int r;
    b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL) {
        ASN1err(ASN1_F_B64_WRITE_ASN1, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    out = BIO_push(b64, out);
    r = i2d_ASN1_bio_stream(out, val, in, flags, it);
    (void)BIO_flush(out);
    BIO_pop(out);
    BIO_free(b64);
    return r;
}

EXTENSION(sign) {
    int flags = PKCS7_TEXT;
    char *cert, *data, *str, *pstr;
    BIO *in, *out, *tbio;
    X509 *scert;
    EVP_PKEY *skey;
    PKCS7 *p7;
    if (PG_ARGISNULL(0)) ereport(ERROR, (errmsg("cert is null!")));
    cert = TextDatumGetCString(PG_GETARG_DATUM(0));
    if (PG_ARGISNULL(1)) ereport(ERROR, (errmsg("data is null!")));
    data = TextDatumGetCString(PG_GETARG_DATUM(1));
    if (!(tbio = BIO_new_mem_buf(cert, strlen(cert)))) ereport(ERROR, (errmsg("!tbio")));
    if (!(in = BIO_new_mem_buf(data, strlen(data)))) ereport(ERROR, (errmsg("!in")));
    if (!(scert = PEM_read_bio_X509(tbio, NULL, 0, NULL))) ereport(ERROR, (errmsg("!scert")));
    BIO_reset(tbio);
    if (!(skey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL))) ereport(ERROR, (errmsg("!skey")));
    if (!(p7 = PKCS7_sign(scert, skey, NULL, in, flags))) ereport(ERROR, (errmsg("!p7")));
    if (!(out = BIO_new(BIO_s_mem()))) ereport(ERROR, (errmsg("!out")));
    if (!B64_write_ASN1(out, (ASN1_VALUE *)p7, in, flags, ASN1_ITEM_rptr(PKCS7))) ereport(ERROR, (errmsg("!B64_write_ASN1")));
    (long)BIO_get_mem_data(out, &str);
    pstr = pstrdup(str);
    PKCS7_free(p7);
    X509_free(scert);
    EVP_PKEY_free(skey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    (void)pfree(cert);
    (void)pfree(data);
    PG_RETURN_TEXT_P(cstring_to_text(pstr));
}
