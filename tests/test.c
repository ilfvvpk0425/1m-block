/* Unit tests for domainset and sniff. Build with `make test` (ASan + UBSan). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/domainset.h"
#include "../src/sniff.h"

static int fails, checks;
#define CHECK(cond) do { checks++; if (!(cond)) { fails++; \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* ------------------------------------------------------- packet builders */

static size_t build_tcp(uint8_t *buf, int v6, const uint8_t *payload, size_t plen) {
    size_t ip = v6 ? 40 : 20, tcp = 20, total = ip + tcp + plen;
    memset(buf, 0, ip + tcp);
    if (v6) {
        buf[0] = 0x60;
        buf[4] = (uint8_t)((tcp + plen) >> 8); buf[5] = (uint8_t)(tcp + plen);
        buf[6] = 6; buf[7] = 64;
    } else {
        buf[0] = 0x45;
        buf[2] = (uint8_t)(total >> 8); buf[3] = (uint8_t)total;
        buf[8] = 64; buf[9] = 6;
    }
    buf[ip + 12] = 5 << 4;                                   /* data offset = 20 bytes */
    memcpy(buf + ip + tcp, payload, plen);
    return total;
}

static size_t put16(uint8_t *p, size_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; return 2; }

/* Minimal but well-formed TLS 1.2-style ClientHello carrying an SNI extension
 * after an unrelated extension. */
static size_t build_client_hello(uint8_t *b, const char *sni) {
    size_t o = 0, n = strlen(sni);
    b[o++] = 0x16; b[o++] = 0x03; b[o++] = 0x01; o += 2;           /* record, len later */
    size_t hs = o;
    b[o++] = 0x01; o += 3;                                          /* ClientHello, len later */
    b[o++] = 0x03; b[o++] = 0x03;
    memset(b + o, 0xAB, 32); o += 32;                               /* random */
    b[o++] = 32; memset(b + o, 0xCD, 32); o += 32;                  /* session id */
    o += put16(b + o, 4); o += put16(b + o, 0x1301); o += put16(b + o, 0x1302);
    b[o++] = 1; b[o++] = 0;                                         /* compression: null */
    size_t ext_len_at = o; o += 2;
    size_t ext_start = o;
    o += put16(b + o, 0x000a); o += put16(b + o, 4);                /* supported_groups */
    o += put16(b + o, 2); o += put16(b + o, 0x001d);
    o += put16(b + o, 0x0000); o += put16(b + o, n + 5);            /* server_name */
    o += put16(b + o, n + 3); b[o++] = 0; o += put16(b + o, n);
    memcpy(b + o, sni, n); o += n;
    put16(b + ext_len_at, o - ext_start);
    size_t hlen = o - hs - 4;
    b[hs + 1] = (uint8_t)(hlen >> 16); b[hs + 2] = (uint8_t)(hlen >> 8); b[hs + 3] = (uint8_t)hlen;
    put16(b + 3, o - 5);
    return o;
}

static sniff_kind sniff_str(const uint8_t *pkt, size_t len, char *host) {
    size_t hl = 0;
    host[0] = '\0';
    return sniff_packet(pkt, len, host, &hl);
}

/* ------------------------------------------------------------ domainset */

static void test_domainset(void) {
    domainset ds;
    CHECK(ds_init(&ds, 4) == 0);
    CHECK(ds_add(&ds, "Example.COM", 11) == 1);
    CHECK(ds_add(&ds, "example.com.", 12) == 0);                     /* duplicate after normalize */
    CHECK(ds_add(&ds, "vk.com", 6) == 1);
    CHECK(ds_add(&ds, "bad domain", 10) == 0);                       /* invalid char */
    CHECK(ds_add(&ds, "", 0) == 0);
    CHECK(ds.size == 2);

    CHECK(ds_match(&ds, "example.com", 11, 0) == 11);
    CHECK(ds_match(&ds, "EXAMPLE.com.", 12, 0) == 11);
    CHECK(ds_match(&ds, "www.example.com", 15, 0) == 0);             /* exact mode */
    CHECK(ds_match(&ds, "www.example.com", 15, 1) == 11);            /* suffix mode */
    CHECK(ds_match(&ds, "a.b.c.example.com", 17, 1) == 11);
    CHECK(ds_match(&ds, "xexample.com", 12, 1) == 0);                /* label boundary only */
    CHECK(ds_match(&ds, "xvk.com", 7, 1) == 0);
    CHECK(ds_match(&ds, "m.vk.com", 8, 1) == 6);
    CHECK(ds_match(&ds, "com", 3, 1) == 0);
    CHECK(ds_match(&ds, "example.org", 11, 1) == 0);

    /* growth past the initial capacity keeps every entry reachable */
    char name[64];
    for (int i = 0; i < 50000; i++) {
        int n = snprintf(name, sizeof name, "host%d.test", i);
        CHECK(ds_add(&ds, name, (size_t)n) == 1);
    }
    int missing = 0;
    for (int i = 0; i < 50000; i++) {
        int n = snprintf(name, sizeof name, "host%d.test", i);
        if (!ds_match(&ds, name, (size_t)n, 0)) missing++;
    }
    CHECK(missing == 0);
    CHECK(ds.size == 50002);
    ds_free(&ds);

    /* file loading: CSV, plain, comments, blank, CRLF, overlong lines */
    const char *path = "test_list.tmp";
    FILE *fp = fopen(path, "wb");
    fputs("1,google.com\r\n2,youtube.com\n# comment\n\n   plain.example\n3,Google.com\n", fp);
    for (int i = 0; i < 2000; i++) fputc('a', fp);
    fputs("\n4,after-long.line\n", fp);
    fclose(fp);
    CHECK(ds_init(&ds, 0) == 0);
    CHECK(ds_load_file(&ds, path) == 4);
    CHECK(ds_match(&ds, "google.com", 10, 0) && ds_match(&ds, "youtube.com", 11, 0));
    CHECK(ds_match(&ds, "plain.example", 13, 0) && ds_match(&ds, "after-long.line", 15, 0));
    CHECK(ds_load_file(&ds, "does-not-exist.tmp") == -1);
    ds_free(&ds);
    remove(path);
}

/* ---------------------------------------------------------------- sniff */

static void test_http(void) {
    uint8_t pkt[2048];
    char host[SNIFF_HOST_MAX + 1];
    const char *req;
    size_t n;

    req = "GET / HTTP/1.1\r\nHost: test.gilgil.net\r\nUser-Agent: x\r\n\r\n";
    n = build_tcp(pkt, 0, (const uint8_t *)req, strlen(req));
    CHECK(sniff_str(pkt, n, host) == SNIFF_HTTP && strcmp(host, "test.gilgil.net") == 0);

    n = build_tcp(pkt, 1, (const uint8_t *)req, strlen(req));          /* IPv6 */
    CHECK(sniff_str(pkt, n, host) == SNIFF_HTTP && strcmp(host, "test.gilgil.net") == 0);

    req = "POST /a HTTP/1.1\r\nAccept: */*\r\nhOsT:   Example.com:8080  \r\n\r\n";
    n = build_tcp(pkt, 0, (const uint8_t *)req, strlen(req));
    CHECK(sniff_str(pkt, n, host) == SNIFF_HTTP && strcmp(host, "Example.com") == 0);

    req = "GET / HTTP/1.1\nHost: lf-only.test\n\n";                      /* bare LF */
    n = build_tcp(pkt, 0, (const uint8_t *)req, strlen(req));
    CHECK(sniff_str(pkt, n, host) == SNIFF_HTTP && strcmp(host, "lf-only.test") == 0);

    req = "GET / HTTP/1.1\r\nX-Host: evil.test\r\nHost: real.test\r\n\r\n"; /* header name must match fully */
    n = build_tcp(pkt, 0, (const uint8_t *)req, strlen(req));
    CHECK(sniff_str(pkt, n, host) == SNIFF_HTTP && strcmp(host, "real.test") == 0);

    req = "GET / HTTP/1.1\r\nAccept: */*\r\n\r\nHost: body.test\r\n";    /* Host after headers end */
    n = build_tcp(pkt, 0, (const uint8_t *)req, strlen(req));
    CHECK(sniff_str(pkt, n, host) == SNIFF_NONE);

    req = "GET / HTTP/1.1\r\nHost: cut.te";                               /* segment ends mid-header */
    n = build_tcp(pkt, 0, (const uint8_t *)req, strlen(req));
    CHECK(sniff_str(pkt, n, host) == SNIFF_NONE);

    req = "HTTP/1.1 200 OK\r\nHost: response.test\r\n\r\n";             /* not a request */
    n = build_tcp(pkt, 0, (const uint8_t *)req, strlen(req));
    CHECK(sniff_str(pkt, n, host) == SNIFF_NONE);

    req = "GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n";
    n = build_tcp(pkt, 0, (const uint8_t *)req, strlen(req));
    CHECK(sniff_str(pkt, n, host) == SNIFF_NONE);

    /* the 2021 version assumed a 20-byte TCP header; with TCP options (32 bytes) it misread */
    req = "GET / HTTP/1.1\r\nHost: opts.test\r\n\r\n";
    n = build_tcp(pkt, 0, (const uint8_t *)req, strlen(req));
    memmove(pkt + 20 + 32, pkt + 40, n - 40);
    memset(pkt + 40, 1, 12);                                             /* NOP options */
    pkt[20 + 12] = 8 << 4;
    n += 12; pkt[2] = (uint8_t)(n >> 8); pkt[3] = (uint8_t)n;
    CHECK(sniff_str(pkt, n, host) == SNIFF_HTTP && strcmp(host, "opts.test") == 0);

    /* not TCP, fragments, bad header lengths */
    req = "GET / HTTP/1.1\r\nHost: a.test\r\n\r\n";
    n = build_tcp(pkt, 0, (const uint8_t *)req, strlen(req));
    CHECK(sniff_str(pkt, n, host) == SNIFF_HTTP);
    pkt[9] = 17;  CHECK(sniff_str(pkt, n, host) == SNIFF_NONE);  pkt[9] = 6;
    pkt[7] = 0x10; CHECK(sniff_str(pkt, n, host) == SNIFF_NONE); pkt[7] = 0;
    pkt[0] = 0x4F; CHECK(sniff_str(pkt, n, host) == SNIFF_NONE); pkt[0] = 0x45;
    pkt[32] = 0xF0; CHECK(sniff_str(pkt, n, host) == SNIFF_NONE);
    CHECK(sniff_str(pkt, 0, host) == SNIFF_NONE);
}

static void test_tls(void) {
    uint8_t ch[1024], pkt[2048];
    char host[SNIFF_HOST_MAX + 1];
    size_t chn = build_client_hello(ch, "www.Netflix.com");
    size_t n = build_tcp(pkt, 0, ch, chn);
    CHECK(sniff_str(pkt, n, host) == SNIFF_TLS && strcmp(host, "www.Netflix.com") == 0);
    n = build_tcp(pkt, 1, ch, chn);
    CHECK(sniff_str(pkt, n, host) == SNIFF_TLS && strcmp(host, "www.Netflix.com") == 0);

    /* every truncation must fail cleanly (SNI is the last extension) */
    int bad = 0;
    for (size_t cut = 0; cut < chn; cut++) {
        size_t hl; char h[SNIFF_HOST_MAX + 1];
        if (sniff_tls(ch, cut, h, &hl) != SNIFF_NONE) bad++;
    }
    CHECK(bad == 0);

    /* lying length fields */
    uint8_t tmp[1024];
    memcpy(tmp, ch, chn); tmp[5] = 0x02;                                 /* ServerHello */
    { size_t hl; CHECK(sniff_tls(tmp, chn, host, &hl) == SNIFF_NONE); }
    memcpy(tmp, ch, chn); tmp[5 + 4 + 34] = 0xFF;                        /* session id len 255 */
    { size_t hl; CHECK(sniff_tls(tmp, chn, host, &hl) == SNIFF_NONE); }
    memcpy(tmp, ch, chn); tmp[chn - 15 - 2] = 0xFF;                      /* name len too big */
    { size_t hl; CHECK(sniff_tls(tmp, chn, host, &hl) == SNIFF_NONE); }
}

/* Random mutations and truncations of valid packets: must never crash or
 * read out of bounds (ASan would abort). Also checks output stays sane. */
static void test_fuzz(void) {
    uint8_t ch[1024], base[3][2048], pkt[2048];
    size_t blen[3];
    const char *req = "GET /index.html HTTP/1.1\r\nHost: fuzz.example\r\nAccept: */*\r\n\r\n";
    blen[0] = build_tcp(base[0], 0, (const uint8_t *)req, strlen(req));
    size_t chn = build_client_hello(ch, "fuzz.example");
    blen[1] = build_tcp(base[1], 0, ch, chn);
    blen[2] = build_tcp(base[2], 1, ch, chn);

    srand(1234);
    int weird = 0;
    for (int it = 0; it < 300000; it++) {
        int b = it % 3;
        size_t n = blen[b];
        memcpy(pkt, base[b], n);
        int muts = 1 + rand() % 4;
        for (int m = 0; m < muts; m++) pkt[rand() % n] = (uint8_t)rand();
        if (rand() % 4 == 0) n = (size_t)rand() % (n + 1);
        uint8_t *heap = malloc(n ? n : 1);                               /* exact-size buffer for ASan */
        memcpy(heap, pkt, n);
        char host[SNIFF_HOST_MAX + 1]; size_t hl = 0;
        if (sniff_packet(heap, n, host, &hl) != SNIFF_NONE && (hl == 0 || hl > SNIFF_HOST_MAX || strlen(host) != hl))
            weird++;
        free(heap);
    }
    CHECK(weird == 0);
}

int main(void) {
    test_domainset();
    test_http();
    test_tls();
    test_fuzz();
    printf("%d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
