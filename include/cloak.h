/*
 *  ircd-ratbox: A slightly useful ircd.
 *  cloak.h: Keyed host cloaking.
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

#ifndef INCLUDED_cloak_h
#define INCLUDED_cloak_h

struct Client;

/* Width, in hex characters, of each label of a cloaked host. The leftmost
 * label identifies the individual user, the two after it identify
 * progressively wider chunks of their network. 32 bits on the user label
 * keeps accidental collisions negligible on any plausible network size.
 */
#define CLOAK_LEN_USER	8
#define CLOAK_LEN_NET	6

/* "uuuuuuuu.nnnnnn.tttttt." - everything we prepend to the suffix */
#define CLOAK_PREFIX_LEN	(CLOAK_LEN_USER + CLOAK_LEN_NET + CLOAK_LEN_NET + 3)

/* Longest suffix that still leaves the result inside HOSTLEN */
#define CLOAK_MAX_SUFFIX	(HOSTLEN - CLOAK_PREFIX_LEN)

/* Refuse keys short enough to be worth brute forcing. */
#define CLOAK_MIN_KEYLEN	16

/* Adopt (or reject) the cloak settings currently in ConfigFileEntry.
 * Called at the end of load_conf_settings(), so it runs both at startup and
 * on every rehash. A rehash that introduces a bad key keeps the running one.
 */
void cloak_apply_config(void);

/* True when cloaking was asked for but we have never had a usable key, i.e.
 * we would be letting users on uncloaked. Startup checks this and refuses.
 */
int cloak_is_broken(void);

/* Replace client_p->host with its cloak. Returns 1 if the host was changed. */
int cloak_client(struct Client *client_p);

#endif /* INCLUDED_cloak_h */
