#include <postgres.h>
#include <fmgr.h>

#include <catalog/pg_type.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <utils/builtins.h>

#define EXTENSION(function) Datum (function)(PG_FUNCTION_ARGS); PG_FUNCTION_INFO_V1(function); Datum (function)(PG_FUNCTION_ARGS)

PG_MODULE_MAGIC;

EXTENSION(sign) {
    long len;
    int flags = PKCS7_DETACHED | PKCS7_STREAM;
    char *cert, *data, *str;
    BIO *in, *out, *tbio;
    X509 *scert;
    EVP_PKEY *skey;
    PKCS7 *p7;
    if (PG_ARGISNULL(0)) ereport(ERROR, (errmsg("cert is null!")));
    cert = TextDatumGetCString(PG_GETARG_DATUM(0));
    if (PG_ARGISNULL(1)) ereport(ERROR, (errmsg("data is null!")));
    data = TextDatumGetCString(PG_GETARG_DATUM(1));
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    if (!(tbio = BIO_new_mem_buf(cert, strlen(cert)))) ereport(ERROR, (errmsg("!tbio")));
    if (!(in = BIO_new_mem_buf(data, strlen(data)))) ereport(ERROR, (errmsg("!in")));
    if (!(scert = PEM_read_bio_X509(tbio, NULL, 0, NULL))) ereport(ERROR, (errmsg("!scert")));
    BIO_reset(tbio);
    if (!(skey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL))) ereport(ERROR, (errmsg("!skey")));
    if (!(p7 = PKCS7_sign(scert, skey, NULL, in, flags))) ereport(ERROR, (errmsg("!p7")));
    if (!(out = BIO_new(BIO_s_mem()))) ereport(ERROR, (errmsg("!out")));
    if (!(flags & PKCS7_STREAM)) BIO_reset(in);
    if (!SMIME_write_PKCS7(out, p7, in, flags)) ereport(ERROR, (errmsg("!SMIME_write_PKCS7")));
    len = BIO_get_mem_data(out, (char **)&str);
    elog(LOG, "len=%li, str=%s", len, str);
    PKCS7_free(p7);
    X509_free(scert);
    EVP_PKEY_free(skey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    (void)pfree(cert);
    (void)pfree(data);
    elog(LOG, "len=%li, str=%s", len, str);
    PG_RETURN_TEXT_P(cstring_to_text(str));
}
