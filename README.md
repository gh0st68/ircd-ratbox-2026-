# ircd-ratbox 3.0.10 — modernized

ircd-ratbox 3.0.10 (the final upstream release, January 2016) with the changes
needed to build and run safely against a current toolchain — OpenSSL 3.x,
GCC 12+, and Debian multiarch.

Upstream ratbox is dormant: 3.0.10 is still the newest release on ratbox.org,
`download/devel/` is empty, and the ircd-ratbox GitHub org has no tags,
releases, or branches. This tree is that final release plus the fixes below.

Verified on Debian 12 (bookworm), GCC 12.2, OpenSSL 3.0.20, autoconf 2.71.

## Build

```sh
./configure --enable-openssl --with-sqlite3
make
make install
```

`--with-sqlite3` links the system SQLite instead of the bundled 3.10.0 copy
(see below). Drop it to use the bundled one.

## What changed vs stock 3.0.10

### TLS hardening (`libratbox/src/openssl.c`)

Stock 3.0.10 predates OpenSSL 1.1 and only ever disabled SSLv2, leaving TLS 1.0
and 1.1 reachable. Note that Debian sets no system-wide `MinProtocol` or
`SECLEVEL` in `/etc/ssl/openssl.cnf`, so the OS does not compensate for this.

- `SSLv23_server_method()` / `TLSv1_client_method()` → `TLS_server_method()` /
  `TLS_client_method()`. The client context was previously pinned to TLS 1.0.
- TLS 1.2 set as the minimum on both context paths, via `SSL_OP_NO_TLSv1` /
  `SSL_OP_NO_TLSv1_1` and `SSL_CTX_set_min_proto_version()`.
- Cipher list replaced with an AEAD-first list:
  `ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:HIGH:!aNULL:!MD5:!RC4:!3DES`
- Curve pinning to `prime256v1` removed on OpenSSL ≥ 1.1.0, which negotiates
  curves automatically. The `EC_KEY` / `SSL_CTX_set_tmp_ecdh()` pair it needed
  is deprecated in 3.x, and pinning one curve only narrowed what could be agreed.
- `SSL_load_error_strings()` / `SSL_library_init()` guarded — both are implicit
  since 1.1.0.
- `SSLeay_version()` → `OpenSSL_version()`.
- Fixed a latent NULL-dereference: `SSL_CTX_set_options()` was called on
  `ssl_server_ctx` even when `SSL_CTX_new()` had just failed.

### RNG failure handling

`RAND_bytes()` returns 1 for success and 0 for failure, but the wrappers tested
for `< 0` and `== -1`, so a failed draw was reported as success and left the
caller using an uninitialized buffer.

- `libratbox/src/openssl.c` — both `rb_get_random()` and
  `rb_get_pseudo_random()` now test strictly against 1. The latter also moves
  off the deprecated `RAND_pseudo_bytes()`.
- `resolver/res.c` — `generate_random_id()` and `generate_random_port()` ignored
  the return value entirely, so an RNG failure meant predictable DNS query IDs
  and source ports, and could spin forever in the port loop. Both now abort
  rather than continue; the ircd restarts the resolver helper as it would for
  any other helper fault.
- `src/ircd.c` — `seed_random()` tested for `-1`, which the function never
  returns, so the urandom/clock fallback could never fire.

### CHALLENGE moved to the EVP API

`SHA1_Init/Update/Final`, `RSA_size()`, `RSA_public_encrypt()`,
`PEM_read_bio_RSA_PUBKEY()` and `RSA_free()` are all deprecated in OpenSSL 3.0
and will break when they are removed.

- `struct oper_conf.rsa_pubkey` is now an `EVP_PKEY *`.
- Encryption goes through `EVP_PKEY_CTX` with OAEP padding; hashing through
  `EVP_Digest*`.
- `PEM_read_bio_PUBKEY()` reads the same SubjectPublicKeyInfo
  (`BEGIN PUBLIC KEY`) files as before, so **existing operator key files keep
  working** — the challenge is byte-identical and clients need no changes.
- A key file that is not RSA is now rejected at config time with a clear error
  instead of failing later at oper time.

### Build system

- `acinclude.m4` / `configure` — the SQLite library search path predated Debian
  multiarch, so `--with-sqlite3` found `/usr/include/sqlite3.h` but not
  `/usr/lib/<triplet>/libsqlite3.so`, then silently fell back to the bundled
  copy. The triplet from `$CC -print-multiarch` is now searched first. This
  matters: the bundled SQLite is 3.10.0 from January 2016.

Both `acinclude.m4` and the generated `configure` were patched, so no
`autoreconf` is required.

## Testing

Built and run against a scratch install: TLS 1.0/1.1 rejected; TLS 1.2
negotiates ECDHE-RSA-AES256-GCM-SHA384 and TLS 1.3 negotiates
TLS_AES_256_GCM_SHA384; the cipher list expands to no weak suites; IRC sessions
over both plaintext and TLS; a full RSA CHALLENGE oper round-trip returning
`381 RPL_YOUREOPER`, with a wrong response correctly rejected; the ban database
created through the system SQLite; and the resolver surviving live DNS queries.

## Known limitations (inherited from upstream, not addressed here)

- **No TLS peer certificate verification anywhere.** Server links over SSL get
  encryption but not authentication — they still rely on the connect block
  password and IP.
- The `HIGH` term in the cipher list re-admits non-forward-secret plain-RSA key
  exchange. Ordering plus `SSL_OP_CIPHER_SERVER_PREFERENCE` means modern
  clients still get ECDHE-AEAD, but add `!kRSA:!PSK:!SRP` if you want strict
  forward secrecy.
- The outbound client context has no minimum protocol version, so a server link
  could still accept TLS 1.0 from the peer. Stock was pinned to TLS 1.0 only, so
  this is an improvement either way.
- No SASL, no certfp, and `multi-prefix` is the only IRCv3 capability
  advertised. If you need those, Solanum is the actively maintained descendant
  of this codebase.

## License

Unchanged from upstream ircd-ratbox — GPL-2.0. See `LICENSE` and `CREDITS`.

## Contact

irc.twistednet.org — `#dev` / `#twisted`
