/* 1m-block: drop HTTP/HTTPS connections to domains in a (million-entry) list.
 *
 * Packets are handed to user space with an iptables/nft NFQUEUE rule. For each
 * packet we pull the host from the HTTP Host header or the TLS SNI, look it up
 * in a hash set (with parent-domain matching), and return DROP or ACCEPT. */
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "domainset.h"
#include "sniff.h"

static struct {
    unsigned queue;
    int exact, verbose, monitor;
    const char *list;
} opt = { .queue = 0 };

static struct {
    unsigned long long packets, http, tls, blocked;
} counts;

static domainset ds;
static volatile sig_atomic_t stop;

static void on_signal(int sig) { (void)sig; stop = 1; }

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void usage(void) {
    fprintf(stderr,
        "syntax : 1m-block [-q queue] [-x] [-n] [-v] <site list file>\n"
        "sample : 1m-block -q 0 top-1m.csv\n"
        "  -q N  NFQUEUE number (default 0)\n"
        "  -x    exact match only (default also blocks subdomains)\n"
        "  -n    monitor mode: log matches but accept every packet\n"
        "  -v    log every packet that carries a host name\n"
        "list    'rank,domain' CSV or one domain per line\n");
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    (void)nfmsg; (void)data;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return -1;
    uint32_t id = ntohl(ph->packet_id);

    unsigned char *pkt;
    int len = nfq_get_payload(nfa, &pkt);
    uint32_t verdict = NF_ACCEPT;
    counts.packets++;

    char raw[SNIFF_HOST_MAX + 1], host[DS_MAX_DOMAIN + 1];
    size_t rlen, hlen;
    sniff_kind k = len > 0 ? sniff_packet(pkt, (size_t)len, raw, &rlen) : SNIFF_NONE;
    if (k != SNIFF_NONE && (hlen = ds_normalize(raw, rlen, host)) > 0) {
        if (k == SNIFF_HTTP) counts.http++; else counts.tls++;
        size_t m = ds_match(&ds, host, hlen, !opt.exact);
        const char *kind = k == SNIFF_HTTP ? "http" : "tls ";
        if (m) {
            counts.blocked++;
            if (!opt.monitor) verdict = NF_DROP;
            /* a dropped segment is retransmitted many times, and retransmissions of
             * several connections interleave: log a host at most once per 5 s */
            static struct { char host[DS_MAX_DOMAIN + 1]; double t; } recent[8];
            static unsigned next;
            double t = now_sec();
            int seen = 0;
            for (unsigned i = 0; i < 8; i++)
                if (t - recent[i].t < 5.0 && strcmp(recent[i].host, host) == 0) { seen = 1; break; }
            if (!seen) {
                printf("%s %s %s (rule: %s)\n", opt.monitor ? "MATCH" : "BLOCK", kind, host, host + hlen - m);
                fflush(stdout);
                memcpy(recent[next].host, host, hlen + 1);
                recent[next].t = t;
                next = (next + 1) % 8;
            }
        } else if (opt.verbose) {
            printf("pass  %s %s\n", kind, host);
            fflush(stdout);
        }
    }
    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

int main(int argc, char **argv) {
    int c;
    while ((c = getopt(argc, argv, "q:xnvh")) != -1) {
        switch (c) {
        case 'q': opt.queue = (unsigned)strtoul(optarg, NULL, 10); break;
        case 'x': opt.exact = 1; break;
        case 'n': opt.monitor = 1; break;
        case 'v': opt.verbose = 1; break;
        default: usage(); return c == 'h' ? 0 : 1;
        }
    }
    if (optind != argc - 1) { usage(); return 1; }
    opt.list = argv[optind];

    double t0 = now_sec();
    if (ds_init(&ds, 1024) < 0) { fprintf(stderr, "out of memory\n"); return 1; }
    long n = ds_load_file(&ds, opt.list);
    if (n < 0) { fprintf(stderr, "cannot load %s: %s\n", opt.list, strerror(errno)); return 1; }
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    printf("loaded %ld domains in %.2f s (set %.1f MiB, max RSS %.1f MiB)\n", n, now_sec() - t0,
           (double)ds_memory(&ds) / 1048576.0, (double)ru.ru_maxrss / 1024.0);

    struct nfq_handle *h = nfq_open();
    if (!h) { perror("nfq_open (need root / CAP_NET_ADMIN)"); return 1; }
    struct nfq_q_handle *qh = nfq_create_queue(h, (uint16_t)opt.queue, &cb, NULL);
    if (!qh) { perror("nfq_create_queue (is another process bound to this queue?)"); nfq_close(h); return 1; }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) { perror("nfq_set_mode"); return 1; }
    /* if user space falls behind, let packets through instead of dropping them */
    if (nfq_set_queue_flags(qh, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN) < 0)
        fprintf(stderr, "warning: kernel does not support fail-open\n");
    nfnl_rcvbufsiz(nfq_nfnlh(h), 4 << 20);

    struct sigaction sa = { .sa_handler = on_signal };     /* no SA_RESTART: recv() returns EINTR */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    printf("listening on queue %u (%s, %s)\n", opt.queue, opt.exact ? "exact" : "subdomains too",
           opt.monitor ? "monitor only" : "dropping matches");
    fflush(stdout);

    int fd = nfq_fd(h);
    char buf[0x10000 + 4096] __attribute__((aligned));
    while (!stop) {
        ssize_t rv = recv(fd, buf, sizeof buf, 0);
        if (rv >= 0) { nfq_handle_packet(h, buf, (int)rv); continue; }
        if (errno == EINTR) continue;
        if (errno == ENOBUFS) { fprintf(stderr, "warning: losing packets (ENOBUFS)\n"); continue; }
        perror("recv");
        break;
    }

    printf("\npackets %llu (with host: http %llu, tls %llu), %s packets %llu\n",
           counts.packets, counts.http, counts.tls,
           opt.monitor ? "matched" : "blocked", counts.blocked);
    nfq_destroy_queue(qh);
    nfq_close(h);
    ds_free(&ds);
    return 0;
}
