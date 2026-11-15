#include "sniff.h"

#include <string.h>

#define IPPROTO_TCP_ 6

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t rd24(const uint8_t *p) { return (uint32_t)p[0] << 16 | (uint32_t)p[1] << 8 | p[2]; }

/* ---------------------------------------------------------------- IP/TCP */

int sniff_tcp_payload(const uint8_t *pkt, size_t len, const uint8_t **payload, size_t *plen) {
    sniff_flow f;
    return sniff_tcp(pkt, len, &f, payload, plen);
}

int sniff_tcp(const uint8_t *pkt, size_t len, sniff_flow *flow, const uint8_t **payload, size_t *plen) {
    if (len < 1) return -1;
    size_t off;
    unsigned proto;
    size_t end = len;
    memset(flow, 0, sizeof *flow);

    switch (pkt[0] >> 4) {
    case 4: {
        if (len < 20) return -1;
        size_t ihl = (size_t)(pkt[0] & 0x0F) * 4;
        size_t tot = rd16(pkt + 2);
        if (ihl < 20 || ihl > len) return -1;
        if (tot >= ihl && tot < end) end = tot;              /* ignore link-layer padding */
        if (rd16(pkt + 6) & 0x1FFF) return -1;               /* non-first fragment: no TCP header */
        proto = pkt[9];
        off = ihl;
        flow->version = 4;
        memcpy(flow->src, pkt + 12, 4);
        memcpy(flow->dst, pkt + 16, 4);
        break;
    }
    case 6: {
        if (len < 40) return -1;
        size_t tot = 40 + (size_t)rd16(pkt + 4);
        if (tot < end) end = tot;
        proto = pkt[6];
        off = 40;
        flow->version = 6;
        memcpy(flow->src, pkt + 8, 16);
        memcpy(flow->dst, pkt + 24, 16);
        for (int hops = 0; proto == 0 || proto == 43 || proto == 60; hops++) {   /* HBH, routing, dst-opts */
            if (hops > 8 || off + 8 > end) return -1;
            unsigned next = pkt[off];
            size_t hlen = ((size_t)pkt[off + 1] + 1) * 8;
            if (off + hlen > end) return -1;
            proto = next;
            off += hlen;
        }
        break;                                               /* fragment (44) etc. fall through as non-TCP */
    }
    default:
        return -1;
    }

    if (proto != IPPROTO_TCP_ || off + 20 > end) return -1;
    size_t doff = (size_t)(pkt[off + 12] >> 4) * 4;
    if (doff < 20 || off + doff > end) return -1;
    flow->sport = rd16(pkt + off);
    flow->dport = rd16(pkt + off + 2);
    flow->seq = (uint32_t)rd16(pkt + off + 4) << 16 | rd16(pkt + off + 6);
    flow->flags = pkt[off + 13];
    *payload = pkt + off + doff;
    *plen = end - off - doff;
    return 0;
}

/* ------------------------------------------------------------------ HTTP */

static const char *const methods[] = {
    "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
};

static int lower(int c) { return (c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c; }

static sniff_kind copy_host(const uint8_t *s, size_t n, char *out, size_t *out_len, sniff_kind k) {
    if (n == 0 || n > SNIFF_HOST_MAX) return SNIFF_NONE;
    for (size_t i = 0; i < n; i++)                           /* printable ASCII only, no NUL/space */
        if (s[i] < 0x21 || s[i] > 0x7E) return SNIFF_NONE;
    memcpy(out, s, n);
    out[n] = '\0';
    *out_len = n;
    return k;
}

sniff_kind sniff_http(const uint8_t *p, size_t len, char *out, size_t *out_len) {
    int is_req = 0;
    for (size_t i = 0; i < sizeof methods / sizeof *methods; i++) {
        size_t m = strlen(methods[i]);
        if (len >= m && memcmp(p, methods[i], m) == 0) { is_req = 1; break; }
    }
    if (!is_req) return SNIFF_NONE;

    /* walk header lines: each starts right after "\n" */
    size_t i = 0;
    while (i < len && p[i] != '\n') i++;                   /* skip request line */
    while (++i < len) {
        size_t line = i;
        while (i < len && p[i] != '\n') i++;
        size_t lend = i;                                     /* p[lend] == '\n' or lend == len */
        if (lend == len) return SNIFF_MORE;                  /* header line cut off by segment end */
        if (lend > line && p[lend - 1] == '\r') lend--;
        if (lend == line) return SNIFF_NONE;                 /* blank line: end of headers, no Host */
        if (lend - line >= 5 && lower(p[line]) == 'h' && lower(p[line + 1]) == 'o' &&
            lower(p[line + 2]) == 's' && lower(p[line + 3]) == 't' && p[line + 4] == ':') {
            size_t v = line + 5;
            while (v < lend && (p[v] == ' ' || p[v] == '\t')) v++;
            size_t e = lend;
            while (e > v && (p[e - 1] == ' ' || p[e - 1] == '\t')) e--;
            if (v < e && p[v] == '[') return SNIFF_NONE;     /* IPv6 literal: not a domain */
            for (size_t k = v; k < e; k++) if (p[k] == ':') { e = k; break; }   /* strip :port */
            return copy_host(p + v, e - v, out, out_len, SNIFF_HTTP);
        }
    }
    return SNIFF_MORE;                                       /* headers continue in a later segment */
}

/* ------------------------------------------------------------------- TLS */

sniff_kind sniff_tls(const uint8_t *p, size_t len, char *out, size_t *out_len) {
    /* TLS record header. If the record (or the ClientHello inside it) is longer
     * than what we have, a failure to find the SNI means "need more bytes". */
    if (len < 5) return (len >= 1 && p[0] == 0x16 && (len < 2 || p[1] == 0x03)) ? SNIFF_MORE : SNIFF_NONE;
    if (p[0] != 0x16 || p[1] != 0x03) return SNIFF_NONE;
    size_t rec_full = 5 + (size_t)rd16(p + 3);
    int more = rec_full > len;
#define FAIL return more ? SNIFF_MORE : SNIFF_NONE
    size_t rec_end = more ? len : rec_full;                 /* parse what we have */

    /* Handshake header: ClientHello */
    size_t o = 5;
    if (o + 1 > rec_end) FAIL;
    if (p[o] != 0x01) return SNIFF_NONE;
    if (o + 4 > rec_end) FAIL;
    size_t hs_full = o + 4 + rd24(p + o + 1);
    if (hs_full > len) more = 1;                             /* ClientHello spans records/segments */
    size_t hs_end = hs_full < rec_end ? hs_full : rec_end;
    o += 4;

    o += 2 + 32;                                             /* client_version, random */
    if (o + 1 > hs_end) FAIL;
    o += 1 + p[o];                                           /* session_id */
    if (o + 2 > hs_end) FAIL;
    o += 2 + rd16(p + o);                                    /* cipher_suites */
    if (o + 1 > hs_end) FAIL;
    o += 1 + p[o];                                           /* compression_methods */
    if (o + 2 > hs_end) FAIL;
    size_t ext_end = o + 2 + rd16(p + o);
    if (ext_end > hs_end) ext_end = hs_end;
    o += 2;

    while (o + 4 <= ext_end) {
        uint16_t type = rd16(p + o);
        size_t elen = rd16(p + o + 2);
        o += 4;
        if (o + elen > ext_end) FAIL;
        if (type == 0x0000) {                                /* server_name */
            size_t q = o, list_end = o + elen;
            if (q + 2 > list_end) return SNIFF_NONE;
            size_t l_end = q + 2 + rd16(p + q);
            if (l_end > list_end) return SNIFF_NONE;
            q += 2;
            while (q + 3 <= l_end) {
                uint8_t name_type = p[q];
                size_t nlen = rd16(p + q + 1);
                q += 3;
                if (q + nlen > l_end) return SNIFF_NONE;
                if (name_type == 0) return copy_host(p + q, nlen, out, out_len, SNIFF_TLS);
                q += nlen;
            }
            return SNIFF_NONE;
        }
        o += elen;
    }
    FAIL;
#undef FAIL
}

/* ---------------------------------------------------------------- glue */

sniff_kind sniff_payload(const uint8_t *p, size_t len, char *out, size_t *out_len) {
    if (len == 0) return SNIFF_NONE;
    if (p[0] == 0x16) return sniff_tls(p, len, out, out_len);
    return sniff_http(p, len, out, out_len);
}

sniff_kind sniff_packet(const uint8_t *pkt, size_t len, char *out, size_t *out_len) {
    const uint8_t *pl;
    size_t plen;
    if (sniff_tcp_payload(pkt, len, &pl, &plen) < 0) return SNIFF_NONE;
    return sniff_payload(pl, plen, out, out_len);
}
