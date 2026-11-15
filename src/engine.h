/* engine: per-packet blocking decision, including reassembly of requests and
 * ClientHellos that span several TCP segments.
 *
 * Kept free of netfilter code so it can be unit-tested with synthetic packets. */
#ifndef ENGINE_H
#define ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "domainset.h"
#include "sniff.h"

#define ENGINE_FLOWS     256     /* connections with a pending (incomplete) request at once */
#define ENGINE_BUF       8192    /* bytes kept per connection; ClientHellos are 0.5-2 KB */
#define ENGINE_SEGMENTS  8       /* give up reassembling after this many segments */
#define ENGINE_TIMEOUT   10.0    /* seconds before a pending / blocked entry expires */

typedef struct {
    int used, blocked, segments;
    sniff_flow key;              /* seq field unused here */
    uint32_t next_seq;
    double t;
    size_t len;
    uint8_t buf[ENGINE_BUF];
} engine_flow;

typedef struct {
    engine_flow flows[ENGINE_FLOWS];
    const domainset *ds;
    int suffix;
    unsigned long long reassembled, gave_up, evicted;
} engine;

typedef struct {
    int drop;                    /* 1 = NF_DROP */
    sniff_kind kind;             /* what was found (SNIFF_MORE = buffered, waiting) */
    int reassembled;             /* host came from more than one segment */
    int flow_blocked;            /* dropped because the connection was already blocked */
    char host[DS_MAX_DOMAIN + 1];/* normalized host when kind is HTTP/TLS */
    size_t host_len, match_len;  /* match_len > 0: host matched rule host[host_len - match_len..] */
} engine_result;

void engine_init(engine *e, const domainset *ds, int suffix);
void engine_packet(engine *e, const uint8_t *pkt, size_t len, double now, engine_result *r);

#endif
