/* Micro-benchmarks: list loading, lookup cost (hash set vs. the 2021 linear scan),
 * and per-packet parse cost. Usage: ./build-bench data/top-1m.csv */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#include "../src/domainset.h"
#include "../src/sniff.h"

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static double rss_mib(void) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return (double)ru.ru_maxrss / 1024.0;
}

static volatile size_t sink;                      /* keeps the optimizer honest */

static uint64_t rng = 88172645463325252ULL;
static uint64_t xorshift(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

/* read the domain column into an array (for query generation and the baseline) */
static char **read_domains(const char *path, size_t *count) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    size_t cap = 1 << 20, n = 0;
    char **v = malloc(cap * sizeof *v), line[1024], norm[DS_MAX_DOMAIN + 1];
    while (fgets(line, sizeof line, fp)) {
        char *s = strchr(line, ',');
        s = s ? s + 1 : line;
        size_t len = strcspn(s, "\r\n");
        size_t m = ds_normalize(s, len, norm);
        if (!m) continue;
        if (n == cap) v = realloc(v, (cap *= 2) * sizeof *v);
        v[n++] = strdup(norm);
    }
    fclose(fp);
    *count = n;
    return v;
}

/* the 2021 approach (with its infinite-loop bug fixed): compare against every entry */
static int linear_contains(char **v, size_t n, const char *host) {
    for (size_t i = 0; i < n; i++)
        if (strcmp(v[i], host) == 0) return 1;
    return 0;
}

static size_t build_ipv4_tcp(uint8_t *buf, const uint8_t *payload, size_t plen) {
    size_t total = 40 + plen;
    memset(buf, 0, 40);
    buf[0] = 0x45; buf[2] = (uint8_t)(total >> 8); buf[3] = (uint8_t)total; buf[9] = 6;
    buf[32] = 5 << 4;
    memcpy(buf + 40, payload, plen);
    return total;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <list.csv>\n", argv[0]); return 1; }

    /* ---------------------------------------------------------- loading */
    double rss0 = rss_mib();
    domainset ds;
    ds_init(&ds, 1024);
    double t = now();
    long added = ds_load_file(&ds, argv[1]);
    double load_s = now() - t;
    printf("load      : %ld domains in %.3f s, set %.1f MiB (table %.1f + arena %.1f), RSS +%.1f MiB\n",
           added, load_s, (double)ds_memory(&ds) / 1048576.0,
           (double)(ds.cap * sizeof *ds.tab) / 1048576.0, (double)ds.arena_cap / 1048576.0,
           rss_mib() - rss0);

    size_t nd;
    char **dom = read_domains(argv[1], &nd);
    if (!dom || nd == 0) { fprintf(stderr, "cannot read %s\n", argv[1]); return 1; }

    /* ---------------------------------------------------------- queries */
    enum { Q = 1 << 20 };
    char **q = malloc(Q * sizeof *q);
    for (size_t i = 0; i < Q; i++) {
        char buf[300];
        const char *d = dom[xorshift() % nd];
        switch (i % 4) {
        case 0: snprintf(buf, sizeof buf, "%s", d); break;                         /* exact hit */
        case 1: snprintf(buf, sizeof buf, "www.%s", d); break;                     /* subdomain hit */
        case 2: snprintf(buf, sizeof buf, "img.cdn.x%llu.%s",                      /* deep miss-ish */
                         (unsigned long long)(xorshift() % 100000), "unlisted-site.net"); break;
        default: snprintf(buf, sizeof buf, "x%llu-%s",                             /* miss */
                          (unsigned long long)(xorshift() % 1000000), d); break;
        }
        q[i] = strdup(buf);
    }

    double exact_ns = 0;
    for (int suffix = 0; suffix <= 1; suffix++) {
        size_t hits = 0;
        int reps = 5;
        t = now();
        for (int r = 0; r < reps; r++)
            for (size_t i = 0; i < Q; i++) hits += ds_match(&ds, q[i], strlen(q[i]), suffix) != 0;
        double el = now() - t;
        sink += hits;
        if (!suffix) exact_ns = el / (reps * (double)Q) * 1e9;
        printf("hash set  : %s match, %.0f ns/lookup (%.1f M lookups/s), hit rate %.1f%%\n",
               suffix ? "suffix" : "exact ", el / (reps * (double)Q) * 1e9,
               reps * (double)Q / el / 1e6, 100.0 * (double)hits / (reps * (double)Q));
    }

    /* baseline: miss = full scan; average over a few queries */
    {
        int nq = 50;
        size_t hits = 0;
        t = now();
        for (int i = 0; i < nq; i++) hits += linear_contains(dom, nd, q[4 * i + 3]);   /* misses */
        double el = now() - t;
        sink += hits;
        double per = el / nq;
        printf("linear    : miss %.2f ms/lookup (%.0f lookups/s) -> %.0fx slower than hash exact\n",
               per * 1e3, 1.0 / per, per * 1e9 / exact_ns);
        int nh = 50;
        t = now();
        for (int i = 0; i < nh; i++) hits += linear_contains(dom, nd, dom[xorshift() % nd]); /* hits */
        el = now() - t;
        sink += hits;
        printf("linear    : hit  %.2f ms/lookup on average (random rank)\n", el / nh * 1e3);
    }

    /* ---------------------------------------------------------- parsing */
    {
        uint8_t http_pkt[1500], tls_pkt[1500], other_pkt[1500];
        const char *req = "GET /index.html HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n"
                          "Accept: text/html,application/xhtml+xml\r\nAccept-Language: ko-KR,ko;q=0.9\r\n"
                          "Host: www.example.com\r\nConnection: keep-alive\r\n\r\n";
        size_t hn = build_ipv4_tcp(http_pkt, (const uint8_t *)req, strlen(req));

        /* realistic-size ClientHello: 512 bytes, SNI after ~20 other extension bytes */
        uint8_t ch[600]; size_t o = 0;
        const char *sni = "www.example.com"; size_t sl = strlen(sni);
        ch[o++] = 0x16; ch[o++] = 3; ch[o++] = 1; o += 2;
        size_t hs = o; ch[o++] = 1; o += 3; ch[o++] = 3; ch[o++] = 3;
        memset(ch + o, 7, 32); o += 32; ch[o++] = 32; memset(ch + o, 9, 32); o += 32;
        ch[o++] = 0; ch[o++] = 32; for (int i = 0; i < 32; i++) ch[o++] = (uint8_t)i;   /* 16 suites */
        ch[o++] = 1; ch[o++] = 0;
        size_t el_at = o; o += 2; size_t es = o;
        ch[o++] = 0; ch[o++] = 0x17; ch[o++] = 0; ch[o++] = 0;                         /* ems */
        ch[o++] = 0; ch[o++] = 0x0a; ch[o++] = 0; ch[o++] = 8; ch[o++] = 0; ch[o++] = 6;
        ch[o++] = 0; ch[o++] = 0x1d; ch[o++] = 0; ch[o++] = 0x17; ch[o++] = 0; ch[o++] = 0x18;
        ch[o++] = 0; ch[o++] = 0; ch[o++] = 0; ch[o++] = (uint8_t)(sl + 5);
        ch[o++] = 0; ch[o++] = (uint8_t)(sl + 3); ch[o++] = 0; ch[o++] = 0; ch[o++] = (uint8_t)sl;
        memcpy(ch + o, sni, sl); o += sl;
        size_t pad = 512 - o - 4;                                                       /* padding ext */
        ch[o++] = 0; ch[o++] = 0x15; ch[o++] = (uint8_t)(pad >> 8); ch[o++] = (uint8_t)pad;
        memset(ch + o, 0, pad); o += pad;
        ch[el_at] = (uint8_t)((o - es) >> 8); ch[el_at + 1] = (uint8_t)(o - es);
        size_t hl = o - hs - 4;
        ch[hs + 1] = 0; ch[hs + 2] = (uint8_t)(hl >> 8); ch[hs + 3] = (uint8_t)hl;
        ch[3] = (uint8_t)((o - 5) >> 8); ch[4] = (uint8_t)(o - 5);
        size_t tn = build_ipv4_tcp(tls_pkt, ch, o);

        uint8_t junk[1200]; for (size_t i = 0; i < sizeof junk; i++) junk[i] = (uint8_t)(xorshift() | 0x80);
        size_t on = build_ipv4_tcp(other_pkt, junk, sizeof junk);

        struct { const char *name; const uint8_t *p; size_t n; } cases[] = {
            { "http GET (" , http_pkt, hn }, { "tls CH   (", tls_pkt, tn }, { "other    (", other_pkt, on },
        };
        for (int c = 0; c < 3; c++) {
            char host[SNIFF_HOST_MAX + 1]; size_t hlen = 0, ok = 0;
            int reps = 10000000;
            t = now();
            for (int r = 0; r < reps; r++) ok += sniff_packet(cases[c].p, cases[c].n, host, &hlen) != SNIFF_NONE;
            double e = now() - t;
            sink += ok;
            printf("parse     : %s%4zu B) %.1f ns/packet, found host %s\n", cases[c].name, cases[c].n,
                   e / reps * 1e9, ok ? host : "-");
        }
    }

    printf("RSS peak  : %.1f MiB\n", rss_mib());
    return 0;
}
