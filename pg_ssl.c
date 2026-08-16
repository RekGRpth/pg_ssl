#include <postgres.h>
#include <fmgr.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <utils/builtins.h>

#define EXTENSION(function) Datum (function)(PG_FUNCTION_ARGS); PG_FUNCTION_INFO_V1(function); Datum (function)(PG_FUNCTION_ARGS)

PG_MODULE_MAGIC;

static const char *
openssl_errstr(void)
{
    unsigned long code = ERR_get_error();
    return code ? ERR_error_string(code, NULL) : "unknown error";
}

static void
sign_cleanup(BIO *in, BIO *out, BIO *cbio, BIO *kbio, BIO *b64, X509 *scert, EVP_PKEY *skey, PKCS7 *p7, char *cert, char *key, char *data)
{
    if (b64) BIO_free(b64);
    if (out) BIO_free(out);
    if (p7) PKCS7_free(p7);
    if (scert) X509_free(scert);
    if (skey) EVP_PKEY_free(skey);
    if (in) BIO_free(in);
    if (kbio) BIO_free(kbio);
    if (cbio) BIO_free(cbio);
    if (cert) pfree(cert);
    if (key) pfree(key);
    if (data) pfree(data);
}

EXTENSION(sign) {
    int flags = PKCS7_TEXT;
    char *cert = NULL, *key = NULL, *data = NULL, *str;
    long len;
    text *result = NULL;
    BIO *in = NULL, *out = NULL, *out2, *cbio = NULL, *kbio = NULL, *b64 = NULL;
    X509 *scert = NULL;
    EVP_PKEY *skey = NULL;
    PKCS7 *p7 = NULL;
    PG_TRY();
    {
        ERR_clear_error();
        if (PG_ARGISNULL(0)) ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("cert must not be null")));
        cert = TextDatumGetCString(PG_GETARG_DATUM(0));
        if (PG_ARGISNULL(1)) ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("key must not be null")));
        key = TextDatumGetCString(PG_GETARG_DATUM(1));
        if (PG_ARGISNULL(2)) ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("data must not be null")));
        data = TextDatumGetCString(PG_GETARG_DATUM(2));
        if (!(cbio = BIO_new_mem_buf(cert, strlen(cert)))) ereport(ERROR, (errcode(ERRCODE_OUT_OF_MEMORY), errmsg("could not create BIO for cert: %s", openssl_errstr())));
        if (!(kbio = BIO_new_mem_buf(key, strlen(key)))) ereport(ERROR, (errcode(ERRCODE_OUT_OF_MEMORY), errmsg("could not create BIO for key: %s", openssl_errstr())));
        if (!(in = BIO_new_mem_buf(data, strlen(data)))) ereport(ERROR, (errcode(ERRCODE_OUT_OF_MEMORY), errmsg("could not create BIO for data: %s", openssl_errstr())));
        if (!(scert = PEM_read_bio_X509(cbio, NULL, 0, NULL))) ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("could not parse certificate: %s", openssl_errstr())));
        if (!(skey = PEM_read_bio_PrivateKey(kbio, NULL, 0, NULL))) ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("could not parse private key: %s", openssl_errstr())));
        OPENSSL_cleanse(key, strlen(key));
        if (!(p7 = PKCS7_sign(scert, skey, NULL, in, flags))) ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("could not sign data: %s", openssl_errstr())));
        if (!(out = BIO_new(BIO_s_mem()))) ereport(ERROR, (errcode(ERRCODE_OUT_OF_MEMORY), errmsg("could not create output BIO: %s", openssl_errstr())));
        if (!(b64 = BIO_new(BIO_f_base64()))) ereport(ERROR, (errcode(ERRCODE_OUT_OF_MEMORY), errmsg("could not create base64 filter BIO: %s", openssl_errstr())));
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        out2 = BIO_push(b64, out);
        if (!i2d_ASN1_bio_stream(out2, (ASN1_VALUE *)p7, in, flags, ASN1_ITEM_rptr(PKCS7))) ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR), errmsg("could not encode signature: %s", openssl_errstr())));
        if (BIO_flush(out2) != 1) ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR), errmsg("could not flush signature output: %s", openssl_errstr())));
        len = BIO_get_mem_data(out, &str);
        result = cstring_to_text_with_len(str, len);
    }
    PG_CATCH();
    {
        sign_cleanup(in, out, cbio, kbio, b64, scert, skey, p7, cert, key, data);
        PG_RE_THROW();
    }
    PG_END_TRY();
    sign_cleanup(in, out, cbio, kbio, b64, scert, skey, p7, cert, key, data);
    PG_RETURN_TEXT_P(result);
}
