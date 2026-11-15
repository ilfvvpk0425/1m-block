/* sniff: extract the destination host name from a raw IP packet.
 *
 * Supports IPv4 and IPv6 (with hop-by-hop / routing / destination-options
 * extension headers), TCP, and two application formats:
 *   - HTTP/1.x request: the Host header
 *   - TLS ClientHello:  the server_name (SNI) extension
 * Every read is bounds-checked; truncated or malformed input yields SNIFF_NONE. */
#ifndef SNIFF_H
#define SNIFF_H

#include <stddef.h>
#include <stdint.h>

/* SNIFF_MORE: the payload starts an HTTP request / TLS ClientHello, but the host
 * is not in the bytes seen so far (header or record continues in a later segment). */
typedef enum { SNIFF_NONE = 0, SNIFF_HTTP = 1, SNIFF_TLS = 2, SNIFF_MORE = 3 } sniff_kind;

#define SNIFF_HOST_MAX 253

/* TCP connection identity + position, filled by sniff_tcp() */
typedef struct {
    uint8_t  version;            /* 4 or 6 */
    uint8_t  src[16], dst[16];   /* IPv4 uses the first 4 bytes */
    uint16_t sport, dport;
    uint32_t seq;
    uint8_t  flags;              /* TCP flags byte (FIN 0x01, SYN 0x02, RST 0x04) */
} sniff_flow;

/* Like sniff_tcp_payload, and also reports the connection 4-tuple and sequence number. */
int sniff_tcp(const uint8_t *pkt, size_t len, sniff_flow *flow, const uint8_t **payload, size_t *plen);

/* out must hold SNIFF_HOST_MAX + 1 bytes. On success writes a NUL-terminated
 * host (port stripped, not yet lowercased) and its length to *out_len. */
sniff_kind sniff_packet(const uint8_t *pkt, size_t len, char *out, size_t *out_len);

/* The same, starting from a TCP payload (exposed for tests and benchmarks). */
sniff_kind sniff_payload(const uint8_t *p, size_t len, char *out, size_t *out_len);
sniff_kind sniff_http(const uint8_t *p, size_t len, char *out, size_t *out_len);
sniff_kind sniff_tls(const uint8_t *p, size_t len, char *out, size_t *out_len);

/* Locates the TCP payload inside an IP packet. Returns 0 on success. */
int sniff_tcp_payload(const uint8_t *pkt, size_t len, const uint8_t **payload, size_t *plen);

#endif
