/* domainset: a compact hash set of domain names for fast blocklist lookups.
 *
 * Strings live in one growing arena; the table stores (hash, arena offset)
 * pairs with open addressing (linear probing). Domains are normalized to
 * lowercase without a trailing dot when added and when looked up. */
#ifndef DOMAINSET_H
#define DOMAINSET_H

#include <stddef.h>
#include <stdint.h>

#define DS_MAX_DOMAIN 253

typedef struct {
    uint64_t hash;
    uint32_t off;      /* 0 = empty slot (arena byte 0 is reserved) */
    uint32_t len;
} ds_slot;

typedef struct {
    ds_slot *tab;
    size_t cap;        /* power of two */
    size_t size;
    char *arena;
    size_t arena_len, arena_cap;
} domainset;

int  ds_init(domainset *ds, size_t expected);
void ds_free(domainset *ds);

/* Adds a domain. Returns 1 if added, 0 if already present or invalid, -1 on OOM. */
int  ds_add(domainset *ds, const char *name, size_t len);

/* Exact lookup of an already-normalized name. */
int  ds_contains(const domainset *ds, const char *name, size_t len);

/* Looks up host; with suffix != 0 also tries every parent domain on a label
 * boundary ("a.b.example.com" -> "b.example.com" -> "example.com" -> "com").
 * Returns the length of the matched suffix, or 0 when nothing matches. */
size_t ds_match(const domainset *ds, const char *host, size_t len, int suffix);

/* Loads "rank,domain" CSV lines (Tranco / Alexa format) or one domain per line.
 * Blank lines and lines starting with '#' are skipped.
 * Returns number of domains added, or -1 if the file cannot be opened. */
long ds_load_file(domainset *ds, const char *path);

/* Bytes used by the table and the string arena. */
size_t ds_memory(const domainset *ds);

/* Lowercases name into out (cap >= DS_MAX_DOMAIN + 1), strips one trailing dot,
 * rejects characters outside [a-z0-9.-_]. Returns the new length or 0 if invalid. */
size_t ds_normalize(const char *name, size_t len, char *out);

#endif
