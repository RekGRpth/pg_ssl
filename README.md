# pg_ssl

A PostgreSQL extension that exposes OpenSSL PKCS#7 signing as a SQL function.

## Function

```sql
sign(cert text, key text, data text) RETURNS text
```

Signs `data` with the PEM-encoded X.509 certificate `cert` and the matching
PEM-encoded private key `key` (PKCS#7, `PKCS7_sign` with `PKCS7_TEXT`), and
returns the result as a single-line base64-encoded DER blob.

```sql
SELECT sign(
    '-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----',
    '-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----',
    'hello world'
);
```

> **Warning:** `key` carries the private key in plaintext as an ordinary SQL
> argument. If `log_statement`, `log_min_duration_statement`, `auto_explain`,
> or similar is enabled, the key text will end up in the server log and in
> `pg_stat_activity`. Restrict access to `sign()` and to the server log
> accordingly.

## Requirements

- PostgreSQL with the `pg_config`/PGXS build toolchain
- OpenSSL development headers

## Build & install

```sh
make
make install
CREATE EXTENSION pg_ssl;
```

## Test

```sh
make installcheck
```

Runs the `pg_regress` suite in `sql/sign.sql` against an already-running
PostgreSQL instance (set `PGHOST`/`PGPORT`/`PGUSER` as needed).

## License

MIT — see [LICENSE](LICENSE).
