#include "domainset.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t fnv1a(const char *s, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= (unsigned char)s[i]; h *= 1099511628211ULL; }
    return h ? h : 1;
}

static size_t pow2_at_least(size_t n) {
    size_t c = 16;
    while (c < n) c <<= 1;
    return c;
}

int ds_init(domainset *ds, size_t expected) {
    memset(ds, 0, sizeof *ds);
    ds->cap = pow2_at_least(expected * 2 + 1);           /* keep load factor <= 0.5 */
    ds->tab = calloc(ds->cap, sizeof *ds->tab);
    ds->arena_cap = expected * 16 + 64;
    ds->arena = malloc(ds->arena_cap);
    if (!ds->tab || !ds->arena) { ds_free(ds); return -1; }
    ds->arena[0] = '\0';
    ds->arena_len = 1;                                    /* offset 0 means "empty" */
    return 0;
}

void ds_free(domainset *ds) {
    free(ds->tab);
    free(ds->arena);
    memset(ds, 0, sizeof *ds);
}

size_t ds_normalize(const char *name, size_t len, char *out) {
    if (len && name[len - 1] == '.') len--;
    if (len == 0 || len > DS_MAX_DOMAIN) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'))
            return 0;
        out[i] = c;
    }
    if (out[0] == '.') return 0;
    out[len] = '\0';
    return len;
}

static size_t find_slot(const ds_slot *tab, size_t cap, const char *arena,
                        uint64_t h, const char *s, size_t n, int *found) {
    size_t mask = cap - 1, i = (size_t)h & mask;
    for (;;) {
        const ds_slot *e = &tab[i];
        if (e->off == 0) { *found = 0; return i; }
        if (e->hash == h && e->len == n && memcmp(arena + e->off, s, n) == 0) { *found = 1; return i; }
        i = (i + 1) & mask;
    }
}

static int grow_table(domainset *ds) {
    size_t ncap = ds->cap * 2;
    ds_slot *nt = calloc(ncap, sizeof *nt);
    if (!nt) return -1;
    for (size_t i = 0; i < ds->cap; i++) {
        ds_slot e = ds->tab[i];
        if (!e.off) continue;
        size_t j = (size_t)e.hash & (ncap - 1);
        while (nt[j].off) j = (j + 1) & (ncap - 1);
        nt[j] = e;
    }
    free(ds->tab);
    ds->tab = nt; ds->cap = ncap;
    return 0;
}

int ds_add(domainset *ds, const char *name, size_t len) {
    char norm[DS_MAX_DOMAIN + 1];
    size_t n = ds_normalize(name, len, norm);
    if (!n) return 0;
    if ((ds->size + 1) * 2 > ds->cap && grow_table(ds) < 0) return -1;

    uint64_t h = fnv1a(norm, n);
    int found;
    size_t i = find_slot(ds->tab, ds->cap, ds->arena, h, norm, n, &found);
    if (found) return 0;

    if (ds->arena_len + n + 1 > ds->arena_cap) {
        size_t ncap = ds->arena_cap * 2 + n + 1;
        if (ncap > UINT32_MAX) return -1;
        char *na = realloc(ds->arena, ncap);
        if (!na) return -1;
        ds->arena = na; ds->arena_cap = ncap;
    }
    memcpy(ds->arena + ds->arena_len, norm, n + 1);
    ds->tab[i] = (ds_slot){ .hash = h, .off = (uint32_t)ds->arena_len, .len = (uint32_t)n };
    ds->arena_len += n + 1;
    ds->size++;
    return 1;
}

int ds_contains(const domainset *ds, const char *name, size_t len) {
    if (!ds->size) return 0;
    int found;
    find_slot(ds->tab, ds->cap, ds->arena, fnv1a(name, len), name, len, &found);
    return found;
}

size_t ds_match(const domainset *ds, const char *host, size_t len, int suffix) {
    char norm[DS_MAX_DOMAIN + 1];
    size_t n = ds_normalize(host, len, norm);
    if (!n) return 0;
    const char *p = norm;
    size_t m = n;
    for (;;) {
        if (ds_contains(ds, p, m)) return m;
        if (!suffix) return 0;
        const char *dot = memchr(p, '.', m);
        if (!dot) return 0;
        m -= (size_t)(dot + 1 - p);
        p = dot + 1;
    }
}

long ds_load_file(domainset *ds, const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    char line[1024];
    long added = 0;
    while (fgets(line, sizeof line, fp)) {
        size_t n = strcspn(line, "\r\n");
        if (line[n] == '\0' && n == sizeof line - 1) {          /* overlong line: skip rest */
            int c; while ((c = fgetc(fp)) != EOF && c != '\n') {}
            continue;
        }
        line[n] = '\0';
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '\0' || *s == '#') continue;
        char *comma = strchr(s, ',');
        if (comma) s = comma + 1;                                 /* "rank,domain" */
        size_t len = strlen(s);
        while (len && (s[len - 1] == ' ' || s[len - 1] == '\t')) len--;
        int r = ds_add(ds, s, len);
        if (r < 0) { fclose(fp); return -1; }
        added += r;
    }
    fclose(fp);
    return added;
}

size_t ds_memory(const domainset *ds) {
    return ds->cap * sizeof *ds->tab + ds->arena_cap;
}
