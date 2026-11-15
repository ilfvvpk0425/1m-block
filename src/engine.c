#include "engine.h"

#include <string.h>

void engine_init(engine *e, const domainset *ds, int suffix) {
    memset(e, 0, sizeof *e);
    e->ds = ds;
    e->suffix = suffix;
}

static int same_conn(const sniff_flow *a, const sniff_flow *b) {
    return a->version == b->version && a->sport == b->sport && a->dport == b->dport &&
           memcmp(a->src, b->src, 16) == 0 && memcmp(a->dst, b->dst, 16) == 0;
}

/* A connection may live in one of ENGINE_PROBE slots starting at hash(4-tuple).
 * Bounded probing keeps the per-packet cost constant: scanning the whole table
 * on every data packet cost ~20% throughput when every packet is queued. */
#define ENGINE_PROBE 16

static size_t conn_hash(const sniff_flow *k) {
    uint32_t h = 2166136261u;
    const uint8_t *parts[2] = { k->src, k->dst };
    size_t n = k->version == 6 ? 16 : 4;
    for (int p = 0; p < 2; p++)
        for (size_t i = 0; i < n; i++) { h ^= parts[p][i]; h *= 16777619u; }
    h ^= (uint32_t)k->sport << 16 | k->dport;
    h *= 16777619u;
    return h & (ENGINE_FLOWS - 1);
}

static engine_flow *find(engine *e, const sniff_flow *k, double now) {
    size_t h = conn_hash(k);
    for (int i = 0; i < ENGINE_PROBE; i++) {
        engine_flow *f = &e->flows[(h + (size_t)i) & (ENGINE_FLOWS - 1)];
        if (!f->used) continue;
        if (now - f->t > ENGINE_TIMEOUT) { f->used = 0; continue; }
        if (same_conn(&f->key, k)) return f;
    }
    return NULL;
}

static engine_flow *add(engine *e, const sniff_flow *k, double now) {
    size_t h = conn_hash(k);
    engine_flow *victim = &e->flows[h];
    for (int i = 0; i < ENGINE_PROBE; i++) {
        engine_flow *f = &e->flows[(h + (size_t)i) & (ENGINE_FLOWS - 1)];
        if (!f->used || now - f->t > ENGINE_TIMEOUT) { victim = f; goto take; }
        if (f->t < victim->t) victim = f;
    }
    e->evicted++;                                            /* probe window full: reuse the oldest */
take:
    victim->used = 1;
    victim->blocked = 0;
    victim->segments = 0;
    victim->key = *k;
    victim->len = 0;
    victim->t = now;
    return victim;
}

/* serial-number comparison (RFC 1982): a < b */
static int seq_before(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }

static void decide(engine *e, sniff_kind k, const char *raw, size_t rlen, engine_result *r) {
    r->kind = k;
    if (k != SNIFF_HTTP && k != SNIFF_TLS) return;
    r->host_len = ds_normalize(raw, rlen, r->host);
    if (!r->host_len) { r->kind = SNIFF_NONE; return; }
    r->match_len = ds_match(e->ds, r->host, r->host_len, e->suffix);
    r->drop = r->match_len > 0;
}

void engine_packet(engine *e, const uint8_t *pkt, size_t len, double now, engine_result *r) {
    memset(r, 0, sizeof *r);
    sniff_flow k;
    const uint8_t *pl;
    size_t plen;
    if (sniff_tcp(pkt, len, &k, &pl, &plen) < 0) return;

    engine_flow *f = find(e, &k, now);
    if (f && f->blocked) {
        /* keep a blocked connection stalled: drop anything carrying data
         * (including retransmissions); let bare ACK/FIN/RST through so it can close */
        if (plen > 0) { r->drop = 1; r->flow_blocked = 1; }
        if (k.flags & 0x05) f->used = 0;                     /* FIN or RST: forget it */
        return;
    }
    if (plen == 0) return;

    char raw[SNIFF_HOST_MAX + 1];
    size_t rlen = 0;
    sniff_kind kind;

    if (f) {                                                 /* continuing a pending request */
        if (k.seq != f->next_seq) {
            /* retransmission of buffered bytes, or out of order: nothing new to parse */
            if (!seq_before(k.seq, f->next_seq)) { f->used = 0; e->gave_up++; }   /* gap: give up */
            return;
        }
        size_t n = plen;
        if (n > ENGINE_BUF - f->len) n = ENGINE_BUF - f->len;
        memcpy(f->buf + f->len, pl, n);
        f->len += n;
        f->next_seq += (uint32_t)plen;
        f->segments++;
        f->t = now;
        kind = sniff_payload(f->buf, f->len, raw, &rlen);
        r->reassembled = 1;
        if (kind == SNIFF_MORE && (f->len >= ENGINE_BUF || f->segments >= ENGINE_SEGMENTS)) {
            f->used = 0; e->gave_up++;                       /* too long: let it pass */
            r->kind = SNIFF_NONE;
            return;
        }
    } else {
        kind = sniff_payload(pl, plen, raw, &rlen);
        if (kind == SNIFF_MORE) {                            /* start buffering this connection */
            f = add(e, &k, now);
            size_t n = plen < ENGINE_BUF ? plen : ENGINE_BUF;
            memcpy(f->buf, pl, n);
            f->len = n;
            f->next_seq = k.seq + (uint32_t)plen;
            f->segments = 1;
            r->kind = SNIFF_MORE;
            return;
        }
    }

    decide(e, kind, raw, rlen, r);
    if (!f) return;
    if (kind == SNIFF_MORE) return;                          /* still waiting */
    if (r->reassembled && (kind == SNIFF_HTTP || kind == SNIFF_TLS)) e->reassembled++;
    if (r->drop) { f->blocked = 1; f->t = now; }             /* the earlier segments were already accepted */
    else f->used = 0;
}
