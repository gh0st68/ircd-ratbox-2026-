/*
 *  ircd-ratbox: A slightly useful ircd.
 *  cloak.c: Keyed host cloaking.
 *
 *  Copyright (C) 2026 ircd-ratbox development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * Replaces a user's visible host with an opaque, keyed hash of their address,
 * so that other users learn nothing about where they are connecting from.
 *
 * A cloak looks like:
 *
 *	4f2a91c0.9c3d7e.11aa22.users.example.org
 *	|        |      |      `-- cloak_suffix, verbatim from the config
 *	|        |      `--------- their /16   (IPv4) or /32 (IPv6)
 *	|        `---------------- their /24   (IPv4) or /48 (IPv6)
 *	`------------------------- them        (IPv4 /32, IPv6 /64)
 *
 * Every label is HMAC-SHA256 output, so nothing about the real address
 * survives. The point of the nesting is that operators keep the ability to
 * ban a whole network without ever being shown one: *.9c3d7e.11aa22.<suffix>
 * catches everyone in that /24. A single flat hash per user would hide just
 * as much but would make subnet bans impossible, which is why it is not
 * done that way here.
 *
 * The hash input is always the binary address, never the resolved hostname.
 * Reverse DNS is attacker-controlled -- a user who owns their PTR record
 * could otherwise steer their own cloak, or aim it at somebody else's.
 *
 * For IPv6 the narrowest label is the /64 rather than the full address.
 * Hosts routinely rotate the interface identifier (SLAAC privacy
 * extensions), and hashing all 128 bits would hand the same person a brand
 * new cloak every few hours, breaking bans and confusing everyone.
 */

#include "stdinc.h"
#include "struct.h"
#include "client.h"
#include "s_conf.h"
#include "s_log.h"
#include "match.h"
#include "send.h"
#include "cloak.h"

/* ------------------------------------------------------------------------
 * SHA-256 (FIPS 180-4).
 *
 * Implemented here rather than borrowed from OpenSSL on purpose: libratbox
 * can be built against OpenSSL, against GnuTLS, or with no TLS at all, and
 * cloaking has to behave identically in all three. A privacy feature that
 * quietly turns itself off because of a build flag would expose every user
 * on the server, so it must not depend on one.
 * ------------------------------------------------------------------------ */

struct sha256_ctx
{
	uint32_t state[8];
	uint64_t bitlen;
	uint8_t buf[64];
	size_t buflen;
};

#define ROTR32(x, n)	(((x) >> (n)) | ((x) << (32 - (n))))
#define SHA_CH(x, y, z)	(((x) & (y)) ^ (~(x) & (z)))
#define SHA_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA_BSIG0(x)	(ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define SHA_BSIG1(x)	(ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SHA_SSIG0(x)	(ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SHA_SSIG1(x)	(ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

static const uint32_t sha256_k[64] = {
	0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
	0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
	0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
	0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
	0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
	0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
	0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
	0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
	0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
	0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
	0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
	0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
	0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
	0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
	0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
	0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static void
sha256_init(struct sha256_ctx *ctx)
{
	ctx->state[0] = 0x6a09e667U;
	ctx->state[1] = 0xbb67ae85U;
	ctx->state[2] = 0x3c6ef372U;
	ctx->state[3] = 0xa54ff53aU;
	ctx->state[4] = 0x510e527fU;
	ctx->state[5] = 0x9b05688cU;
	ctx->state[6] = 0x1f83d9abU;
	ctx->state[7] = 0x5be0cd19U;
	ctx->bitlen = 0;
	ctx->buflen = 0;
}

static void
sha256_transform(struct sha256_ctx *ctx, const uint8_t *block)
{
	uint32_t w[64];
	uint32_t a, b, c, d, e, f, g, h, t1, t2;
	int i;

	for(i = 0; i < 16; i++)
		w[i] = ((uint32_t)block[i * 4] << 24) |
			((uint32_t)block[i * 4 + 1] << 16) |
			((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];

	for(i = 16; i < 64; i++)
		w[i] = SHA_SSIG1(w[i - 2]) + w[i - 7] + SHA_SSIG0(w[i - 15]) + w[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for(i = 0; i < 64; i++)
	{
		t1 = h + SHA_BSIG1(e) + SHA_CH(e, f, g) + sha256_k[i] + w[i];
		t2 = SHA_BSIG0(a) + SHA_MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

static void
sha256_update(struct sha256_ctx *ctx, const void *datap, size_t len)
{
	const uint8_t *data = datap;
	size_t n;

	ctx->bitlen += (uint64_t)len * 8;

	while(len > 0)
	{
		n = 64 - ctx->buflen;
		if(n > len)
			n = len;

		memcpy(ctx->buf + ctx->buflen, data, n);
		ctx->buflen += n;
		data += n;
		len -= n;

		if(ctx->buflen == 64)
		{
			sha256_transform(ctx, ctx->buf);
			ctx->buflen = 0;
		}
	}
}

static void
sha256_final(struct sha256_ctx *ctx, uint8_t out[32])
{
	uint64_t bitlen = ctx->bitlen;
	uint8_t pad[8];
	static const uint8_t one = 0x80;
	static const uint8_t zero = 0x00;
	int i;

	for(i = 0; i < 8; i++)
		pad[i] = (uint8_t)(bitlen >> (56 - i * 8));

	sha256_update(ctx, &one, 1);
	while(ctx->buflen != 56)
		sha256_update(ctx, &zero, 1);

	/* sha256_update() has been adding to bitlen as we padded; the length
	 * word we append has to be the one captured before any of that.
	 */
	sha256_update(ctx, pad, 8);

	for(i = 0; i < 8; i++)
	{
		out[i * 4] = (uint8_t)(ctx->state[i] >> 24);
		out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
		out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
		out[i * 4 + 3] = (uint8_t)ctx->state[i];
	}
}

static void
hmac_sha256(const void *keyp, size_t keylen, const void *msg, size_t msglen, uint8_t out[32])
{
	struct sha256_ctx ctx;
	uint8_t key[64];
	uint8_t ipad[64], opad[64];
	uint8_t inner[32];
	size_t i;

	memset(key, 0, sizeof(key));

	if(keylen > sizeof(key))
	{
		sha256_init(&ctx);
		sha256_update(&ctx, keyp, keylen);
		sha256_final(&ctx, key);
	}
	else
		memcpy(key, keyp, keylen);

	for(i = 0; i < sizeof(key); i++)
	{
		ipad[i] = key[i] ^ 0x36;
		opad[i] = key[i] ^ 0x5c;
	}

	sha256_init(&ctx);
	sha256_update(&ctx, ipad, sizeof(ipad));
	sha256_update(&ctx, msg, msglen);
	sha256_final(&ctx, inner);

	sha256_init(&ctx);
	sha256_update(&ctx, opad, sizeof(opad));
	sha256_update(&ctx, inner, sizeof(inner));
	sha256_final(&ctx, out);

	memset(key, 0, sizeof(key));
	memset(ipad, 0, sizeof(ipad));
	memset(opad, 0, sizeof(opad));
	memset(inner, 0, sizeof(inner));
	memset(&ctx, 0, sizeof(ctx));
}

/* ------------------------------------------------------------------------
 * Cloak state.
 *
 * Held separately from ConfigFileEntry so that a rehash which introduces a
 * broken key cannot disturb the key the server is already using. Users who
 * are online keep the cloaks they were given, and new users keep getting
 * matching ones, instead of the whole network silently reshuffling.
 * ------------------------------------------------------------------------ */

static char *cloak_key = NULL;
static char *cloak_suffix = NULL;
static int cloak_active = 0;
static int cloak_wanted_but_unusable = 0;

int
cloak_is_broken(void)
{
	return cloak_wanted_but_unusable;
}

void
cloak_apply_config(void)
{
	const char *key = ConfigFileEntry.cloak_key;
	const char *suffix = ConfigFileEntry.cloak_suffix;
	const char *problem = NULL;
	char probe[HOSTLEN + 1];

	/* clear_out_old_conf() drops this on every rehash and set_default_conf()
	 * only runs at startup, so own the fallback here rather than depending
	 * on a default that will not survive the first REHASH.
	 */
	if(EmptyString(suffix))
		suffix = "cloak";

	if(!ConfigFileEntry.cloak_enabled)
	{
		if(cloak_active)
			ilog(L_MAIN, "cloak: disabled by configuration");
		cloak_active = 0;
		cloak_wanted_but_unusable = 0;
		return;
	}

	if(EmptyString(key))
		problem = "cloak_key is not set";
	else if(strlen(key) < CLOAK_MIN_KEYLEN)
		problem = "cloak_key is too short (16 characters minimum)";
	else if(strlen(suffix) > CLOAK_MAX_SUFFIX)
		problem = "cloak_suffix is too long to fit inside a hostname";
	else
	{
		/* A suffix of the wrong shape would hand every user an illegal
		 * host, so prove one full cloak is well formed before adopting it.
		 */
		rb_snprintf(probe, sizeof(probe), "%0*d.%0*d.%0*d.%s",
			    CLOAK_LEN_USER, 0, CLOAK_LEN_NET, 0, CLOAK_LEN_NET, 0, suffix);

		if(!valid_hostname(probe))
			problem = "cloak_suffix does not produce a valid hostname";
	}

	if(problem != NULL)
	{
		if(cloak_active)
		{
			/* Rehash with a bad key: say so loudly and carry on with
			 * what we had. Falling back to no cloak here would strip
			 * every subsequent user.
			 */
			ilog(L_MAIN, "cloak: %s - keeping the previous settings", problem);
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "cloak: %s - keeping the previous settings",
					     problem);
		}
		else
		{
			ilog(L_MAIN, "cloak: %s - cloaking cannot be enabled", problem);
			cloak_wanted_but_unusable = 1;
		}
		return;
	}

	rb_free(cloak_key);
	rb_free(cloak_suffix);
	cloak_key = rb_strdup(key);
	cloak_suffix = rb_strdup(suffix);
	cloak_active = 1;
	cloak_wanted_but_unusable = 0;
}

/* One label of the cloak: HMAC the description of an address range and
 * render the leading bytes as hex.
 */
static void
cloak_label(const char *input, char *out, size_t nchars)
{
	static const char hexdigits[] = "0123456789abcdef";
	uint8_t mac[32];
	size_t i;

	hmac_sha256(cloak_key, strlen(cloak_key), input, strlen(input), mac);

	for(i = 0; i < nchars; i++)
		out[i] = hexdigits[(i & 1) ? (mac[i / 2] & 0x0f) : (mac[i / 2] >> 4)];

	out[nchars] = '\0';
	memset(mac, 0, sizeof(mac));
}

#ifdef RB_IPV6
/* Describe the first nbytes of an IPv6 address as text, so that each prefix
 * width hashes to something distinct.
 */
static void
cloak_v6_prefix(char *buf, size_t buflen, const uint8_t *addr, size_t nbytes)
{
	static const char hexdigits[] = "0123456789abcdef";
	size_t i, p = 0;

	buf[p++] = '6';
	buf[p++] = ':';

	for(i = 0; i < nbytes && p + 3 < buflen; i++)
	{
		buf[p++] = hexdigits[addr[i] >> 4];
		buf[p++] = hexdigits[addr[i] & 0x0f];
	}

	buf[p] = '\0';
}
#endif

int
cloak_client(struct Client *client_p)
{
	char user[CLOAK_LEN_USER + 1];
	char net[CLOAK_LEN_NET + 1];
	char top[CLOAK_LEN_NET + 1];
	char input[128];
	char newhost[HOSTLEN + 1];

	if(!cloak_active || client_p->localClient == NULL)
		return 0;

	switch (GET_SS_FAMILY(&client_p->localClient->ip))
	{
	case AF_INET:
		{
			uint32_t a = ntohl(((struct sockaddr_in *)&client_p->localClient->ip)->
					   sin_addr.s_addr);

			rb_snprintf(input, sizeof(input), "4:%u.%u",
				    (a >> 24) & 0xff, (a >> 16) & 0xff);
			cloak_label(input, top, CLOAK_LEN_NET);

			rb_snprintf(input, sizeof(input), "4:%u.%u.%u",
				    (a >> 24) & 0xff, (a >> 16) & 0xff, (a >> 8) & 0xff);
			cloak_label(input, net, CLOAK_LEN_NET);

			rb_snprintf(input, sizeof(input), "4:%u.%u.%u.%u",
				    (a >> 24) & 0xff, (a >> 16) & 0xff,
				    (a >> 8) & 0xff, a & 0xff);
			cloak_label(input, user, CLOAK_LEN_USER);
			break;
		}

#ifdef RB_IPV6
	case AF_INET6:
		{
			const uint8_t *a = (const uint8_t *)
				&((struct sockaddr_in6 *)&client_p->localClient->ip)->sin6_addr;

			cloak_v6_prefix(input, sizeof(input), a, 4);	/* /32 */
			cloak_label(input, top, CLOAK_LEN_NET);

			cloak_v6_prefix(input, sizeof(input), a, 6);	/* /48 */
			cloak_label(input, net, CLOAK_LEN_NET);

			cloak_v6_prefix(input, sizeof(input), a, 8);	/* /64 */
			cloak_label(input, user, CLOAK_LEN_USER);
			break;
		}
#endif

	default:
		/* Not an address family we can carve into prefixes. Still cloak
		 * it -- leaving the real host in place would defeat the point --
		 * just with no grouping, since we do not know the topology.
		 */
		rb_snprintf(input, sizeof(input), "x2:%s", client_p->sockhost);
		cloak_label(input, top, CLOAK_LEN_NET);

		rb_snprintf(input, sizeof(input), "x1:%s", client_p->sockhost);
		cloak_label(input, net, CLOAK_LEN_NET);

		rb_snprintf(input, sizeof(input), "x0:%s", client_p->sockhost);
		cloak_label(input, user, CLOAK_LEN_USER);
		break;
	}

	rb_snprintf(newhost, sizeof(newhost), "%s.%s.%s.%s", user, net, top, cloak_suffix);

	/* cloak_apply_config() already proved this shape is legal, so a failure
	 * here means something is badly wrong. Refuse rather than install a
	 * malformed host that clients would reject.
	 */
	if(!valid_hostname(newhost))
	{
		ilog(L_MAIN, "cloak: refusing to apply malformed cloak '%s'", newhost);
		return 0;
	}

	rb_strlcpy(client_p->host, newhost, sizeof(client_p->host));

	/* Marks the address as concealed. Two things follow from it: the real
	 * IP goes out to other servers as "0" (see send_umode/introduce paths),
	 * and show_ip() gates who is allowed to see it locally.
	 */
	SetIPSpoof(client_p);

	return 1;
}
