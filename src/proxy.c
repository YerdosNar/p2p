#include "../include/proxy.h"
#include "../include/crypto.h"
#include "../include/msgtype.h"
#include "../include/logger.h"
#include "../include/net.h"
#include "../include/stream_table.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PROXY_OPEN_TIMEOUT_SEC   30
#define PROXY_CONNECT_TIMEOUT_MS 10000

/* ── shared context ──────────────────────────────────────────────── */

typedef struct {
        i32             fd;             /* tunnel fd */
        CryptoSession   *session;
        StreamTable     table;
        pthread_mutex_t tx_lock;        /* serializes tunnel sends */
} ProxyCtx;

/* ── send helpers ────────────────────────────────────────────────── */

/*
 * All tunnel sends go through here. The tx mutex serializes access to
 * the secretstream nonce counter; concurrent pushes would corrupt the
 * session.
 */
static bool proxy_send(ProxyCtx *ctx, u8 type, const u8 *data, u32 len)
{
        pthread_mutex_lock(&ctx->tx_lock);
        bool ok = crypto_send_typed(ctx->fd, type, data, len, ctx->session);
        pthread_mutex_unlock(&ctx->tx_lock);
        return ok;
}

static bool send_open(ProxyCtx *ctx, u32 stream_id,
                      const char *host, u16 port)
{
        size_t hlen = strlen(host);
        if (hlen == 0 || hlen > 255) return false;

        u8 buf[4 + 2 + 1 + 255];
        u32 net_id   = htonl(stream_id);
        u16 net_port = htons(port);
        memcpy(buf,     &net_id,   4);
        memcpy(buf + 4, &net_port, 2);
        buf[6] = (u8)hlen;
        memcpy(buf + 7, host, hlen);

        return proxy_send(ctx, MSG_PROXY_OPEN, buf, (u32)(7 + hlen));
}

static bool send_open_ok(ProxyCtx *ctx, u32 stream_id)
{
        u32 net_id = htonl(stream_id);
        bool ok = proxy_send(ctx, MSG_PROXY_OPEN_OK, (u8 *)&net_id, 4);
        log_debug("Stream %u: send OPEN_OK -> %s", stream_id,
                  ok ? "ok" : "FAIL");
        return ok;
}

static bool send_open_fail(ProxyCtx *ctx, u32 stream_id, const char *reason)
{
        size_t rlen = strlen(reason);
        if (rlen > 255) rlen = 255;

        u8 buf[4 + 1 + 255];
        u32 net_id = htonl(stream_id);
        memcpy(buf, &net_id, 4);
        buf[4] = (u8)rlen;
        memcpy(buf + 5, reason, rlen);

        return proxy_send(ctx, MSG_PROXY_OPEN_FAIL, buf, (u32)(5 + rlen));
}

/*
 * 'len' is bounded by PROXY_DATA_MAX_CHUNK (32 KiB), so u16 fits.
 */
static bool send_data(ProxyCtx *ctx, u32 stream_id,
                      const u8 *data, u16 len)
{
        if (len == 0 || len > PROXY_DATA_MAX_CHUNK) return false;

        /* Build one contiguous frame so the tx mutex covers a single
         * crypto_send_typed call. */
        u8 *frame = malloc(6 + (size_t)len);
        if (!frame) return false;

        u32 net_id  = htonl(stream_id);
        u16 net_len = htons(len);
        memcpy(frame,     &net_id,  4);
        memcpy(frame + 4, &net_len, 2);
        memcpy(frame + 6, data, len);

        bool ok = proxy_send(ctx, MSG_PROXY_DATA, frame, 6u + (u32)len);
        free(frame);
        return ok;
}

static bool send_close(ProxyCtx *ctx, u32 stream_id)
{
        u32 net_id = htonl(stream_id);
        return proxy_send(ctx, MSG_PROXY_CLOSE, (u8 *)&net_id, 4);
}

/* ── stream half-close helpers ──────────────────────────────────── */

/*
 * We've finished sending. Either OPEN -> HALF_TX (peer still may send),
 * or HALF_RX -> DEAD (peer already done). Try both transitions.
 */
static void local_tx_done(ProxyCtx *ctx, u32 id)
{
        if (stream_table_transition(&ctx->table, id,
                                    (1u << STREAM_OPEN), STREAM_HALF_TX))
                return;
        stream_table_transition(&ctx->table, id,
                                (1u << STREAM_HALF_RX), STREAM_DEAD);
}

/*
 * Peer told us they're done sending. Either OPEN -> HALF_RX (we still
 * may send), or HALF_TX -> DEAD (we already done).
 */
static void peer_tx_done(ProxyCtx *ctx, u32 id)
{
        if (stream_table_transition(&ctx->table, id,
                                    (1u << STREAM_OPEN), STREAM_HALF_RX))
                return;
        stream_table_transition(&ctx->table, id,
                                (1u << STREAM_HALF_TX), STREAM_DEAD);
}

/* ────────────────────────────────────────────────────────────────── */
/*  JOINER SIDE                                                       */
/* ────────────────────────────────────────────────────────────────── */

/* ── SOCKS5 handshake ───────────────────────────────────────────── */

static bool socks5_greeting(i32 cfd)
{
        u8 hdr[2];
        if (!net_recv_all(cfd, hdr, 2)) return false;
        if (hdr[0] != 0x05) {
                log_warn("SOCKS: bad version 0x%02x", hdr[0]);
                return false;
        }
        u8 nmethods = hdr[1];
        if (nmethods == 0) return false;

        u8 methods[255];
        if (!net_recv_all(cfd, methods, nmethods)) return false;

        bool has_noauth = false;
        for (u8 i = 0; i < nmethods; i++) {
                if (methods[i] == 0x00) { has_noauth = true; break; }
        }
        u8 reply[2] = { 0x05, has_noauth ? 0x00 : 0xFF };
        if (!net_send_all(cfd, reply, 2)) return false;
        return has_noauth;
}

/*
 * Read CONNECT request, fill host (NUL-terminated) and port.
 * Returns 0 on success, or SOCKS5 reply code on failure.
 */
static u8 socks5_parse_request(i32 cfd,
                               char *host, size_t host_size, u16 *port)
{
        u8 hdr[4];
        if (!net_recv_all(cfd, hdr, 4)) return 0x01;
        if (hdr[0] != 0x05) return 0x01;
        if (hdr[1] != 0x01) return 0x07;        /* CMD must be CONNECT */
        u8 atyp = hdr[3];

        if (atyp == 0x01) {                     /* IPv4 */
                u8 ip[4];
                if (!net_recv_all(cfd, ip, 4)) return 0x01;
                snprintf(host, host_size, "%u.%u.%u.%u",
                         ip[0], ip[1], ip[2], ip[3]);
        } else if (atyp == 0x03) {              /* domain */
                u8 dlen;
                if (!net_recv_all(cfd, &dlen, 1)) return 0x01;
                if (dlen == 0 || (size_t)dlen >= host_size) return 0x01;
                if (!net_recv_all(cfd, (u8 *)host, dlen)) return 0x01;
                host[dlen] = '\0';
        } else if (atyp == 0x04) {              /* IPv6 */
                return 0x08;
        } else {
                return 0x08;
        }

        u8 pb[2];
        if (!net_recv_all(cfd, pb, 2)) return 0x01;
        *port = ((u16)pb[0] << 8) | pb[1];
        return 0x00;
}

static bool socks5_reply(i32 cfd, u8 rep)
{
        u8 r[10] = { 0x05, rep, 0x00, 0x01, 0,0,0,0, 0,0 };
        return net_send_all(cfd, r, 10);
}

/* ── joiner per-SOCKS-client thread ─────────────────────────────── */

typedef struct {
        i32             cfd;
        ProxyCtx        *ctx;
} JoinerClientArg;

static void *joiner_client_thread(void *arg)
{
        JoinerClientArg *jc = arg;
        i32 cfd = jc->cfd;
        ProxyCtx *ctx = jc->ctx;
        free(jc);

        char host[256];
        u16  port = 0;
        u32  stream_id = 0;

        if (!socks5_greeting(cfd)) {
                close(cfd);
                return NULL;
        }

        u8 rep = socks5_parse_request(cfd, host, sizeof(host), &port);
        if (rep != 0x00) {
                socks5_reply(cfd, rep);
                close(cfd);
                return NULL;
        }

        log_debug("SOCKS CONNECT %s:%u", host, port);

        if (!stream_table_insert(&ctx->table, 0, cfd,
                                 STREAM_OPENING, &stream_id)) {
                log_warn("Stream table full; rejecting SOCKS client");
                socks5_reply(cfd, 0x01);
                close(cfd);
                return NULL;
        }

        if (!send_open(ctx, stream_id, host, port)) {
                log_error("Failed to send OPEN for stream %u", stream_id);
                socks5_reply(cfd, 0x01);
                stream_table_transition(&ctx->table, stream_id,
                                        (1u << STREAM_OPENING), STREAM_DEAD);
                return NULL;
        }

        /* Wait for peer's OPEN_OK or OPEN_FAIL. */
        StreamState final;
        if (!stream_table_wait_open(&ctx->table, stream_id,
                                    PROXY_OPEN_TIMEOUT_SEC, &final)) {
                log_warn("Stream %u: OPEN timeout", stream_id);
                socks5_reply(cfd, 0x01);
                send_close(ctx, stream_id);
                stream_table_transition(&ctx->table, stream_id,
                                        (1u << STREAM_OPENING), STREAM_DEAD);
                return NULL;
        }

        if (final != STREAM_OPEN) {
                /* recv thread saw OPEN_FAIL and transitioned us to DEAD;
                 * the cfd was closed there. Trying to reply is harmless. */
                socks5_reply(cfd, 0x01);
                return NULL;
        }

        if (!socks5_reply(cfd, 0x00)) {
                send_close(ctx, stream_id);
                local_tx_done(ctx, stream_id);
                return NULL;
        }

        /* Pump: SOCKS client -> tunnel. recv thread does the reverse. */
        u8 buf[PROXY_DATA_MAX_CHUNK];
        for (;;) {
                ssize_t n = recv(cfd, buf, sizeof(buf), 0);
                if (n > 0) {
                        if (!send_data(ctx, stream_id, buf, (u16)n)) {
                                log_warn("Stream %u: send_data failed",
                                         stream_id);
                                break;
                        }
                        continue;
                }
                /* n == 0 (EOF) or error */
                break;
        }

        send_close(ctx, stream_id);
        local_tx_done(ctx, stream_id);
        return NULL;
}

/* ── joiner: SOCKS accept loop ──────────────────────────────────── */

static int bind_socks_listener(u16 port)
{
        int sfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sfd < 0) {
                log_error("socket: %s", strerror(errno));
                return -1;
        }
        int opt = 1;
        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in sa = {0};
        sa.sin_family      = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);    /* 127.0.0.1 ONLY */
        sa.sin_port        = htons(port);
        if (bind(sfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                log_error("bind 127.0.0.1:%u: %s", port, strerror(errno));
                close(sfd);
                return -1;
        }
        if (listen(sfd, 64) < 0) {
                log_error("listen: %s", strerror(errno));
                close(sfd);
                return -1;
        }
        return sfd;
}

/* ── joiner: tunnel recv loop ───────────────────────────────────── */

static void *joiner_recv_thread(void *arg)
{
        ProxyCtx *ctx = arg;
        for (;;) {
                u8 type;
                u8 *data = NULL;
                u32 len = 0;
                if (!crypto_recv_typed(ctx->fd, &type, &data, &len,
                                       ctx->session)) {
                        log_error("Tunnel recv failed; proxy terminating.");
                        _exit(1);
                }
                log_debug("Joiner recv: type=0x%02x len=%u", type, len);

                if (type == MSG_PROXY_OPEN_OK && len == 4) {
                        u32 net_id; memcpy(&net_id, data, 4);
                        u32 id = ntohl(net_id);
                        stream_table_transition(&ctx->table, id,
                                                (1u << STREAM_OPENING),
                                                STREAM_OPEN);

                } else if (type == MSG_PROXY_OPEN_FAIL && len >= 5) {
                        u32 net_id; memcpy(&net_id, data, 4);
                        u32 id = ntohl(net_id);
                        u8 rlen = data[4];
                        if ((u32)5 + rlen == len) {
                                log_info("Stream %u rejected by peer: %.*s",
                                         id, (int)rlen, data + 5);
                        }
                        stream_table_transition(&ctx->table, id,
                                                (1u << STREAM_OPENING),
                                                STREAM_DEAD);

                } else if (type == MSG_PROXY_DATA && len >= 6) {
                        u32 net_id;   memcpy(&net_id,   data,     4);
                        u16 net_dlen; memcpy(&net_dlen, data + 4, 2);
                        u32 id   = ntohl(net_id);
                        u16 dlen = ntohs(net_dlen);
                        if ((u32)6 + dlen != len) {
                                log_warn("Stream %u: malformed DATA", id);
                        } else {
                                Stream snap;
                                if (stream_table_get(&ctx->table, id, &snap)
                                    && (snap.state == STREAM_OPEN
                                        || snap.state == STREAM_HALF_TX)) {
                                        if (!net_send_all(snap.fd,
                                                          data + 6, dlen)) {
                                                log_warn("Stream %u: write to client failed",
                                                         id);
                                        }
                                }
                        }

                } else if (type == MSG_PROXY_CLOSE && len == 4) {
                        u32 net_id; memcpy(&net_id, data, 4);
                        peer_tx_done(ctx, ntohl(net_id));

                } else {
                        log_warn("Joiner: unknown frame type=0x%02x len=%u",
                                 type, len);
                }
                free(data);
        }
        return NULL;
}

static void run_joiner(ProxyCtx *ctx, u16 socks_port)
{
        int sfd = bind_socks_listener(socks_port);
        if (sfd < 0) return;

        log_info("SOCKS5 listening on 127.0.0.1:%u (loopback only)",
                 socks_port);

        pthread_t rx;
        if (pthread_create(&rx, NULL, joiner_recv_thread, ctx) != 0) {
                log_error("pthread_create recv: %s", strerror(errno));
                close(sfd);
                return;
        }
        pthread_detach(rx);

        for (;;) {
                struct sockaddr_in ca;
                socklen_t cl = sizeof(ca);
                int cfd = accept(sfd, (struct sockaddr *)&ca, &cl);
                if (cfd < 0) {
                        if (errno == EINTR) continue;
                        log_warn("accept: %s", strerror(errno));
                        continue;
                }

                JoinerClientArg *jc = malloc(sizeof(*jc));
                if (!jc) { close(cfd); continue; }
                jc->cfd = cfd;
                jc->ctx = ctx;

                pthread_t tid;
                if (pthread_create(&tid, NULL,
                                   joiner_client_thread, jc) != 0) {
                        log_warn("pthread_create client: %s", strerror(errno));
                        close(cfd);
                        free(jc);
                        continue;
                }
                pthread_detach(tid);
        }
}

/* ────────────────────────────────────────────────────────────────── */
/*  HOST SIDE                                                         */
/* ────────────────────────────────────────────────────────────────── */

/* ── DNS + connect ──────────────────────────────────────────────── */

static int resolve_host(const char *host, u16 port, struct sockaddr_in *out)
{
        struct addrinfo hints = {0};
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags    = AI_ADDRCONFIG;

        char portstr[8];
        snprintf(portstr, sizeof(portstr), "%u", port);

        struct addrinfo *res = NULL;
        int rc = getaddrinfo(host, portstr, &hints, &res);
        if (rc != 0 || !res) {
                log_debug("getaddrinfo(%s): %s", host, gai_strerror(rc));
                return -1;
        }
        memcpy(out, res->ai_addr, sizeof(*out));
        freeaddrinfo(res);
        return 0;
}

static int connect_with_timeout(const struct sockaddr_in *sa, int timeout_ms)
{
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
                close(fd);
                return -1;
        }

        int rc = connect(fd, (const struct sockaddr *)sa, sizeof(*sa));
        if (rc == 0) goto good;
        if (errno != EINPROGRESS) { close(fd); return -1; }

        struct pollfd p = { .fd = fd, .events = POLLOUT };
        rc = poll(&p, 1, timeout_ms);
        if (rc <= 0) { close(fd); return -1; }

        int err = 0;
        socklen_t elen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0
            || err != 0) {
                log_debug("connect: %s", strerror(err));
                close(fd);
                return -1;
        }
good:
        if (fcntl(fd, F_SETFL, flags) < 0) {
                log_warn("Couldn't restore blocking mode on dest fd");
        }
        return fd;
}

/* ── host per-stream pump (destination -> tunnel) ───────────────── */

typedef struct {
        ProxyCtx        *ctx;
        u32             stream_id;
} HostPumpArg;

static void *host_pump_thread(void *arg)
{
        HostPumpArg *hp = arg;
        ProxyCtx *ctx = hp->ctx;
        u32 id = hp->stream_id;
        free(hp);

        Stream snap;
        if (!stream_table_get(&ctx->table, id, &snap)) return NULL;
        i32 dfd = snap.fd;

        u8 buf[PROXY_DATA_MAX_CHUNK];
        for (;;) {
                ssize_t n = recv(dfd, buf, sizeof(buf), 0);
                if (n > 0) {
                        if (!send_data(ctx, id, buf, (u16)n)) {
                                log_warn("Stream %u: send_data failed", id);
                                break;
                        }
                        continue;
                }
                break;          /* EOF or error */
        }

        send_close(ctx, id);
        local_tx_done(ctx, id);
        return NULL;
}

/* ── host dialer thread (spawned per OPEN) ──────────────────────── */

typedef struct {
        ProxyCtx        *ctx;
        u32             stream_id;
        char            host[256];
        u16             port;
} DialerArg;

static void *host_dialer_thread(void *arg)
{
        DialerArg *d = arg;
        ProxyCtx *ctx = d->ctx;
        u32 id = d->stream_id;

        struct sockaddr_in sa;
        if (resolve_host(d->host, d->port, &sa) != 0) {
                log_info("Stream %u: cannot resolve %s", id, d->host);
                send_open_fail(ctx, id, "dns failure");
                free(d);
                return NULL;
        }

        int dfd = connect_with_timeout(&sa, PROXY_CONNECT_TIMEOUT_MS);
        if (dfd < 0) {
                log_info("Stream %u: cannot connect to %s:%u",
                         id, d->host, d->port);
                send_open_fail(ctx, id, "connect failed");
                free(d);
                return NULL;
        }

        log_debug("Stream %u: connected to %s:%u (fd=%d)",
                  id, d->host, d->port, dfd);

        /* Insert BEFORE sending OPEN_OK, so a fast peer's DATA frame
         * can be routed immediately. */
        if (!stream_table_insert(&ctx->table, id, dfd,
                                 STREAM_OPEN, NULL)) {
                close(dfd);
                send_open_fail(ctx, id, "internal");
                free(d);
                return NULL;
        }

        if (!send_open_ok(ctx, id)) {
                stream_table_transition(&ctx->table, id,
                                        (1u << STREAM_OPEN), STREAM_DEAD);
                free(d);
                return NULL;
        }

        HostPumpArg *hp = malloc(sizeof(*hp));
        if (!hp) {
                stream_table_transition(&ctx->table, id,
                                        (1u << STREAM_OPEN), STREAM_DEAD);
                send_close(ctx, id);
                free(d);
                return NULL;
        }
        hp->ctx = ctx;
        hp->stream_id = id;

        pthread_t tid;
        if (pthread_create(&tid, NULL, host_pump_thread, hp) != 0) {
                free(hp);
                stream_table_transition(&ctx->table, id,
                                        (1u << STREAM_OPEN), STREAM_DEAD);
                send_close(ctx, id);
                free(d);
                return NULL;
        }
        pthread_detach(tid);

        free(d);
        return NULL;
}

/* ── host: tunnel recv loop ─────────────────────────────────────── */

static void run_host(ProxyCtx *ctx)
{
        log_info("Proxy host: acting as exit node.");

        for (;;) {
                u8 type;
                u8 *data = NULL;
                u32 len = 0;
                if (!crypto_recv_typed(ctx->fd, &type, &data, &len,
                                       ctx->session)) {
                        log_error("Tunnel recv failed; host exiting.");
                        return;
                }
                log_debug("Host recv: type=0x%02x len=%u", type, len);

                if (type == MSG_PROXY_OPEN && len >= 7) {
                        u32 net_id;   memcpy(&net_id,   data,     4);
                        u16 net_port; memcpy(&net_port, data + 4, 2);
                        u8 hlen = data[6];
                        if ((u32)7 + hlen != len || hlen == 0) {
                                log_warn("Malformed OPEN");
                                free(data); continue;
                        }
                        DialerArg *d = malloc(sizeof(*d));
                        if (!d) { free(data); continue; }
                        d->ctx       = ctx;
                        d->stream_id = ntohl(net_id);
                        d->port      = ntohs(net_port);
                        memcpy(d->host, data + 7, hlen);
                        d->host[hlen] = '\0';

                        pthread_t tid;
                        if (pthread_create(&tid, NULL,
                                           host_dialer_thread, d) != 0) {
                                send_open_fail(ctx, d->stream_id,
                                               "thread create failed");
                                free(d);
                        } else {
                                pthread_detach(tid);
                        }

                } else if (type == MSG_PROXY_DATA && len >= 6) {
                        u32 net_id;   memcpy(&net_id,   data,     4);
                        u16 net_dlen; memcpy(&net_dlen, data + 4, 2);
                        u32 id   = ntohl(net_id);
                        u16 dlen = ntohs(net_dlen);
                        if ((u32)6 + dlen != len) {
                                log_warn("Stream %u: malformed DATA", id);
                        } else {
                                Stream snap;
                                if (stream_table_get(&ctx->table, id, &snap)
                                    && (snap.state == STREAM_OPEN
                                        || snap.state == STREAM_HALF_TX)) {
                                        if (!net_send_all(snap.fd,
                                                          data + 6, dlen)) {
                                                log_warn("Stream %u: write to dest failed",
                                                         id);
                                        }
                                }
                        }

                } else if (type == MSG_PROXY_CLOSE && len == 4) {
                        u32 net_id; memcpy(&net_id, data, 4);
                        peer_tx_done(ctx, ntohl(net_id));

                } else {
                        log_warn("Host: unknown frame type=0x%02x len=%u",
                                 type, len);
                }
                free(data);
        }
}

/* ── entry ──────────────────────────────────────────────────────── */

void proxy_run(i32 fd, CryptoSession *session, bool is_host, u16 socks_port)
{
        ProxyCtx ctx = {0};
        ctx.fd      = fd;
        ctx.session = session;
        if (pthread_mutex_init(&ctx.tx_lock, NULL) != 0) {
                log_error("tx_lock init failed");
                return;
        }
        if (!stream_table_init(&ctx.table)) {
                log_error("stream_table_init failed");
                pthread_mutex_destroy(&ctx.tx_lock);
                return;
        }

        if (is_host) {
                run_host(&ctx);
        } else {
                run_joiner(&ctx, socks_port);
        }

        stream_table_destroy(&ctx.table);
        pthread_mutex_destroy(&ctx.tx_lock);
}
