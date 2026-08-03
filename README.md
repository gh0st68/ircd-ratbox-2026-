```
        ██████╗  █████╗ ████████╗██████╗  ██████╗ ██╗  ██╗
        ██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗╚██╗██╔╝
        ██████╔╝███████║   ██║   ██████╔╝██║   ██║ ╚███╔╝
        ██╔══██╗██╔══██║   ██║   ██╔══██╗██║   ██║ ██╔██╗
        ██║  ██║██║  ██║   ██║   ██████╔╝╚██████╔╝██╔╝ ██╗
        ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
             _
           /` `\_,        i r c d - r a t b o x   3 . 0 . 1 0
          |  o   `\__     ·  openssl 3.x  ·  gcc 12+  ·  multiarch
          |   \__   ,`\   ·  keyed host cloaking
           \    `-.  \ `-.
            `-.___ `-.___`\_,
                  ``      ``
```

ircd-ratbox 3.0.10 — the final upstream release, January 2016 — brought up to
build and run safely on a current toolchain, plus **host cloaking**.

Upstream is dormant. 3.0.10 is still the newest release on ratbox.org,
`download/devel/` is empty, and the ircd-ratbox GitHub organisation has no
tags, releases or branches. This tree is that last release plus the work below.

Verified on Debian 12 (bookworm), GCC 12.2, OpenSSL 3.0.20, autoconf 2.71.

---

## Contents

- [Quick start](#quick-start)
- [Host cloaking](#host-cloaking)
- [What changed vs stock 3.0.10](#what-changed-vs-stock-3010)
- [Known limitations](#known-limitations)
- [Testing](#testing)
- [License](#license)

---

## Quick start

```sh
./configure --enable-openssl --with-sqlite3
make
make install
```

`--with-sqlite3` links the system SQLite. Without it you get the bundled copy,
which is **3.10.0 from January 2016**. Keep the flag unless you have a reason
not to.

---

## Host cloaking

Replaces every user's visible host with an opaque keyed hash of their address,
so other users learn nothing about where they connect from.

```
        4f2a91c0.9c3d7e.11aa22.users.example.org
        │        │      │      └── cloak_suffix, used verbatim
        │        │      └───────── their /16  (IPv4)  ·  /32 (IPv6)
        │        └──────────────── their /24  (IPv4)  ·  /48 (IPv6)
        └───────────────────────── them       (IPv4 /32 · IPv6 /64)
```

Every label is HMAC-SHA256 output — nothing of the real address survives.

The nesting is not decoration. It is there so operators keep the ability to ban
a whole network **without ever being shown one**: `*.9c3d7e.11aa22.<suffix>`
catches everybody in that /24. A single flat hash per user would hide exactly as
much and make subnet bans impossible.

### Configuration

```
general {
	cloak_enabled = yes;
	cloak_key     = "output of: openssl rand -base64 32";
	cloak_suffix  = "users.example.org";   /* default: "cloak" */
};

auth {
	user  = "*@*";
	class = "users";
	flags = cloak_exempt;   /* bots that need a stable, real host */
};
```

### Design notes

| Decision | Why |
| --- | --- |
| Applied at registration, before the TS6 UID burst | The cloak travels as the user's host with **no protocol change**. ratbox has no CHGHOST and no way to alter a host after registration, so anything else would have meant inventing one. |
| Hashes the binary address, never the resolved hostname | Reverse DNS is attacker-controlled. A user who owns their PTR could otherwise steer their own cloak, or aim it at someone else's. |
| IPv6's narrowest label is the /64, not the full address | SLAAC privacy extensions rotate the interface identifier. Hashing all 128 bits would hand the same person a new cloak every few hours and break every ban. |
| SHA-256 and HMAC implemented in `cloak.c`, not taken from OpenSSL | Behaviour is then identical in openssl, gnutls and no-TLS builds. A privacy feature that silently no-ops because of a build flag would expose every user on the server. Verified against FIPS 180-4 and RFC 4231. |
| Fails closed | Enabled with a missing or short key refuses to start. A bad key at rehash keeps the running key; with no key to keep, clients are refused rather than admitted uncloaked. |

### Operators are never blinded

Cloaking hides users from **users**, not from staff. `WHOIS` still reports a
cloaked user's real address to operators regardless of `hide_spoof_ips` — that
setting continues to govern administrator-configured spoofs, where hiding the
truth from opers is sometimes the point.

```
311  alice ~alice e5ee907d.1036a0.2460d1.users.example.org   ← everyone
338  alice pool-1-2-3-4.isp.example :actually using host     ← operators only
338  alice 1.2.3.4 :actually using host                      ← operators only
```

### Bans

Cloaking is applied **after** the K/D-line checks, and `find_kline()` also
matches `sockhost`, so existing **IP and CIDR bans are unaffected**. Bans
written against a cloak mask are re-checked once the cloak is in place, so they
block reconnects and not merely the current session.

---

## What changed vs stock 3.0.10

**At a glance** — 23 files touched (21 modified, `cloak.c` and `cloak.h` new).
Everything below is work on top of the 2016 release.

| Area | Change | Files |
| --- | --- | --- |
| 🔒 **TLS** | TLS 1.2 floor, AEAD-first ciphers, OpenSSL 3.x API, NULL-deref fix | `libratbox/src/openssl.c` |
| 🎲 **RNG** | Failed draws were reported as success; DNS IDs and ports were predictable | `openssl.c`, `resolver/res.c`, `src/ircd.c` |
| 🔑 **CHALLENGE** | `RSA` → `EVP_PKEY`, off the deprecated OpenSSL 3.0 API | `m_oper.c`, `newconf.c`, `s_newconf.c`, `s_newconf.h` |
| 🛠 **Build** | `--with-sqlite3` silently fell back to a 2016 SQLite on multiarch | `acinclude.m4`, `configure` |
| 🎭 **Cloaking** | New feature — keyed host masking, fails closed | `cloak.c`, `cloak.h`, +7 wiring |
| 👁 **Oper visibility** | Cloaked users' real address and hostname stay visible to staff | `client.c`, `client.h`, `struct.h`, `m_whois.c` |

**Summary of fixes, shortest first**

- ✅ TLS 1.0 / 1.1 no longer reachable — client context was *pinned* to TLS 1.0
- ✅ RC4, 3DES and MD5 gone from the cipher list
- ✅ `SSL_CTX_set_options()` no longer called on a context that failed to allocate
- ✅ RNG failures no longer read as success in three separate places
- ✅ DNS query IDs and source ports no longer predictable on RNG failure
- ✅ `seed_random()`'s fallback can actually fire — it tested for a value that never occurs
- ✅ CHALLENGE off deprecated `SHA1_*` / `RSA_public_encrypt()`; existing oper keys still work
- ✅ Non-RSA oper key files rejected at config time instead of failing at oper time
- ✅ `--with-sqlite3` now finds the system library on Debian/Ubuntu multiarch
- ✅ Host cloaking, with subnet bans preserved
- ✅ Cloak-mask K-lines block reconnects, not just the current session
- ✅ Per-host clone limits still enforced under cloaking
- ✅ Operators keep the real address *and* the resolved hostname
- ✅ Cloaking fails closed: refuses to start, refuses to silently expose users

### Commit history

```
15e7f46  cloak: keep the resolved hostname so operators can still see it
d5197b3  cloak: make cloak-mask bans stick, and stop cloaking defeating clone limits
5c9f3f0  cloak: close two fail-open holes found in audit, and harden key handling
a6b883b  cloak: always show a cloaked user's real address to operators
4ac0be3  Add keyed host cloaking
a36841d  ircd-ratbox 3.0.10 modernized for OpenSSL 3.x and current toolchains
```

Tag `precloak` marks the tree before cloaking; `vanilla-updated` tracks the
current known-good state.

---

### TLS — `libratbox/src/openssl.c`

Stock predates OpenSSL 1.1 and only ever disabled SSLv2, leaving TLS 1.0 and
1.1 reachable. Debian sets no system-wide `MinProtocol` or `SECLEVEL`, so the
OS does not compensate.

- `SSLv23_server_method()` / `TLSv1_client_method()` → `TLS_server_method()` /
  `TLS_client_method()`. The client context was previously pinned to TLS 1.0.
- TLS 1.2 minimum on both context paths.
- AEAD-first cipher list; no RC4, 3DES or MD5.
- Curve pinning to `prime256v1` dropped on OpenSSL ≥ 1.1.0, which negotiates
  curves automatically. The `EC_KEY` API it needed is deprecated in 3.x, and
  pinning one curve only narrowed what could be agreed.
- Fixed a latent NULL-dereference: `SSL_CTX_set_options()` ran even when
  `SSL_CTX_new()` had just failed.

### RNG failure handling

`RAND_bytes()` returns 1 for success, but the wrappers tested `< 0` and `== -1`
— so a failed draw was reported as success and the caller used an untouched
buffer.

- Both wrappers now test strictly against 1.
- `resolver/res.c` ignored the result **entirely**, giving predictable DNS query
  IDs and source ports on failure, plus a possible infinite loop in the port
  generator. It now aborts rather than continue; the ircd restarts the resolver.
- `seed_random()` tested for `-1`, which the function never returns, so the
  urandom/clock fallback could never fire.

### CHALLENGE → EVP

`SHA1_*`, `RSA_size()`, `RSA_public_encrypt()`, `PEM_read_bio_RSA_PUBKEY()` and
`RSA_free()` are all deprecated in OpenSSL 3.0.

- `oper_conf.rsa_pubkey` is now an `EVP_PKEY *`.
- `PEM_read_bio_PUBKEY()` reads the same SubjectPublicKeyInfo files, so
  **existing operator key files keep working** and the challenge is
  byte-identical.
- A key file that is not RSA is rejected at config time with a clear error.

### Build

- `--with-sqlite3` **silently fell back to the bundled SQLite.** The library
  search path predated Debian multiarch, so it found `/usr/include/sqlite3.h`
  but not `/usr/lib/<triplet>/libsqlite3.so`, warned, and used the 2016 copy
  anyway.
- The triplet from `$CC -print-multiarch` is now searched first.
- Both `acinclude.m4` **and** the generated `configure` are patched, so **no
  `autoreconf` is required** — the tree builds as shipped.
- `src/Makefile.am` and `src/Makefile.in` both carry `cloak.c`, for the same
  reason.

---

## Known limitations

Nothing here is a surprise waiting to happen — it is written down precisely so
it is not one.

### Cloaking

| Limitation | Detail |
| --- | --- |
| **Key entropy is the whole security of the scheme** | Every user holds a free offline verifier: they know their own address and can see their own cloak. A typed phrase like `mynetworkcloak1` passes the 16-character floor and falls in under a second on one GPU. With the key, all four billion IPv4 addresses hash in about a second, producing a complete reverse-lookup table that de-anonymises everyone, retroactively, from logs. **Generate the key with `openssl rand -base64 32`. Never invent one.** The 16-character minimum catches typos, it is not a recommendation. |
| Every server on a network must share `cloak_key` | Otherwise the same user appears under a different host depending on which server they land on, and bans stop matching. |
| Bans on real **hostnames** no longer match cloaked users | Inherent to hiding the host. IP and CIDR bans are unaffected, and cloak-mask bans work. |
| Hostname masks stop matching in `operator{}` and `shared{}` | A cloaked user cannot `/OPER` against a `*@*.example.com` oper block — use an IP or CIDR mask. Remote K/X/RESV from cloaked opers via `shared{}`/`cluster{}` are likewise refused. |
| Channel bans remain an address-guessing oracle | Any channel op can set `+b *!*@1.2.3.*` and watch whether a cloaked user is blocked, recovering the address in ~32 probes. Inherent to ratbox ban semantics — charybdis behaves identically — and removing it would break IP bans. |
| Only local operators see the real address | The address is sent to other servers as `0`, so an oper on a different server sees `<hidden>`. That is what stops it leaking; the cost is remote ETRACE. |
| `/WHOWAS` hides the address from operators | `whowas` has no cloaked flag, so under the recommended `hide_spoof_ips = yes` it treats a cloak as a spoof. `WHOIS` is unaffected. |
| The key is not scrubbed everywhere | `cloak.c` wipes its own copy, but the same plaintext key also sits in `ConfigFileEntry.cloak_key` and the config parser's buffers. Deleting `cloak_key` and rehashing does **not** revoke it — the running key is kept by design. |
| Fail-closed can mean a connection outage | If cloaking is enabled by rehash with no usable key and none was ever loaded, clients are refused until it is fixed. Deliberate — quietly exposing users is worse — but it is a total new-connection outage while it lasts. |

### TLS

| Limitation | Detail |
| --- | --- |
| No peer-certificate verification anywhere | Server links get encryption but **not authentication**; they still rely on the connect-block password and IP. Unchanged from upstream. |
| The `HIGH` cipher term re-admits plain-RSA key exchange | Ordering plus `SSL_OP_CIPHER_SERVER_PREFERENCE` means modern clients still get ECDHE-AEAD, but a client offering only `AES128-SHA` gets it. Add `!kRSA:!PSK:!SRP` for strict forward secrecy. |
| The outbound client context has no minimum version | A server link could still accept TLS 1.0 from the peer. Stock was pinned to TLS 1.0 only, so this is an improvement either way. |

### Inherited from upstream, not addressed here

- **No SASL, no certfp**, and `multi-prefix` is the only IRCv3 capability
  advertised. If you need those, [Solanum](https://github.com/solanum-ircd/solanum)
  is the actively maintained descendant of this codebase.
- A repeated `CHALLENGE <oper>` leaks `chal_resp` and `opername` —
  `cleanup_challenge()` runs only in the `+response` branch.
- `NICKLEN` defaults to 9; raise it with `--with-nicklen` (max 50).

---

## Testing

Built and run against a live server, not merely compiled:

- TLS 1.0 and 1.1 rejected; 1.2 negotiates `ECDHE-RSA-AES256-GCM-SHA384` and
  1.3 negotiates `TLS_AES_256_GCM_SHA384`; the cipher list expands to no weak
  suites.
- SHA-256 and HMAC-SHA256 checked against FIPS 180-4 and RFC 4231, including
  the multi-block padding boundaries and oversized-key path.
- A full RSA `CHALLENGE` oper login returning `381`, with a wrong response
  correctly rejected.
- Cloaks verified deterministic across reconnects, correctly grouped by /24 and
  /16, `cloak_exempt` and explicit spoofs honoured, operator visibility intact
  under `hide_spoof_ips = yes`.
- Cloak-mask K-lines blocking reconnects, and per-host clone limits enforced.
- Fail-closed behaviour exercised: bad key at startup refuses to boot, bad key
  at rehash keeps the running key, no-key-ever refuses clients.

---

## License

Unchanged from upstream ircd-ratbox — **GPL-2.0**. See `LICENSE` and `CREDITS`.

## Contact

`irc.twistednet.org` — **#dev** / **#twisted**
