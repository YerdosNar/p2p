#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../include/typedefs.h"
#include "../include/logger.h"
#include "../include/net.h"
#include "../include/crypto.h"
#include "../include/protocol.h"
#include "../include/room.h"

#define DEFAULT_PORT   8888
#define LISTEN_BACKLOG 128

typedef struct {
        i32             client_fd;
        char            client_ip[INET_ADDRSTRLEN];
        u16             client_port;
        RoomTable       *rt;
} ClientCtx;

static void usage(const char *exe)
{
        printf("Usage: %s [options]\n\n", exe);
        printf("Options:\n");
        printf("  -p, --port <port>             Listening port (default=%d)\n",
                DEFAULT_PORT);
        printf("  -m, --max-rooms <n>           Max concurrent rooms (default=%d)\n",
                ROOM_DEFAULT_MAX);
        printf("  -L, --log-level <level>       error|warn|info|debug (default=info)\n");
        printf("  -h, --help                    Show this help message\n\n");
        printf("Example:\n  %s -p 1234 -L debug\n", exe);
}

static void parse_args(int argc, char **argv,
                u16 *port, u32 *max_rooms)
{
        *port = DEFAULT_PORT;
        *max_rooms = ROOM_DEFAULT_MAX;

        for (int i = 1; i < argc; i++) {
                if (!strncmp(argv[i], "-h", 2) || !strncmp(argv[i], "--help", 6)) {
                        usage(argv[0]); exit(EXIT_SUCCESS);
                }
                if (!strncmp(argv[i], "-p", 2) || !strncmp(argv[i], "--port", 6)) {
                        if (i + 1 >= argc) {
                                log_warn("'%s' flag needs a numeric value; using %d",
                                        argv[i], DEFAULT_PORT);
                                continue;
                        }
                        int p = atoi(argv[++i]);
                        if (p <= 0 || p > 65535) {
                                log_warn("Invalid port '%s'; using %d.",
                                         argv[i], DEFAULT_PORT);
                                continue;
                        }
                        *port = (u16)p;
                }
                else if (!strncmp(argv[i], "-m", 2) || !strncmp(argv[i], "--max-rooms", 11)) {
                        if (i + 1 >= argc) {
                                log_warn("'%s' flag needs a numeric value; using %d",
                                                argv[i], ROOM_DEFAULT_MAX);
                                continue;
                        }
                        int m = atoi(argv[++i]);
                        if (m <= 0) {
                                log_warn("Invalid number '%s'; using '%d'.",
                                         argv[i], ROOM_DEFAULT_MAX);
                                continue;
                        }
                        *max_rooms = (u32)m;
                }
                else if (!strncmp(argv[i], "-L", 2) || !strncmp(argv[i], "--log-level", 11)) {
                        if (i + 1 >= argc) {
                                log_warn("'%s' flag needs a value; using info.",
                                                argv[i]);
                                continue;
                        }
                        LogLevel lvl;
                        if (!logger_parse_level(argv[++i], &lvl)) {
                                log_warn("Unknown log level '%s'; using info.",
                                                argv[i]);
                                continue;
                        }
                        logger_set_level(lvl);
                }
                else {
                        log_error("Unknown argument: %s", argv[i]);
                        usage(argv[0]);
                        exit(EXIT_FAILURE);
                }
        }
}

static i32 init_listen_fd(u16 port)
{
        struct sockaddr_in sa = {0};
        sa.sin_family         = AF_INET;
        sa.sin_addr.s_addr    = htonl(INADDR_ANY);
        sa.sin_port           = htons(port);
        int fd = net_make_bound_socket(&sa);
        if (fd == -1) return -1;
        if (listen(fd, LISTEN_BACKLOG) == -1) {
                log_error("listen(): %s", strerror(errno));
                close(fd);
                return -1;
        }
        return fd;
}

/*
 * Per-client thread. Owns the ClientCtx (frees it on exit). Runs the
 * crypto handshake, then hands off to the protocol layer.
 */
static void *client_thread(void *arg)
{
        ClientCtx *ctx = arg;
        log_info("Connection from %s:%u", ctx->client_ip, ctx->client_port);

        CryptoSession s;
        if (!crypto_session_handshake(ctx->client_fd, &s)) {
                log_warn("Crypto handshake failed for %s:%u",
                         ctx->client_ip, ctx->client_port);
                close(ctx->client_fd);
                free(ctx);
                return NULL;
        }
        log_debug("Handshake complete with %s:%u",
                  ctx->client_ip, ctx->client_port);

        protocol_handle_client(ctx->client_fd,
                               ctx->client_ip, ctx->client_port,
                               &s, ctx->rt);

        /*
         * Whether the protocol left the fd open (host case) or closed
         * it (joiner case), our thread is done. Zero our copy of the
         * session keys - the room table has a copy of it.
         */
        crypto_session_close(&s);
        room_print_stats(ctx->rt);
        free(ctx);
        return NULL;
}

int main(int argc, char **argv)
{
        u16 port;
        u32 max_rooms;
        parse_args(argc, argv, &port, &max_rooms);

        i32 server_fd = init_listen_fd(port);
        if (server_fd == -1) return 1;
        log_info("Listening on port %u (max rooms = %u)", port, max_rooms);

        RoomTable rt;
        if (!room_table_init(&rt, max_rooms)) {
                log_error("room_table_init failed");
                close(server_fd);
                return 1;
        }

        for (;;) {
                struct sockaddr_in ca;
                socklen_t ca_len = sizeof(ca);
                i32 client_fd = accept(server_fd,
                                       (struct sockaddr *)&ca, &ca_len);
                if (client_fd == -1) {
                        log_warn("accept(): %s", strerror(errno));
                        continue;
                }

                ClientCtx *ctx = calloc(1, sizeof(*ctx));
                if (!ctx) {
                        log_error("calloc(ClientCtx) failed");
                        close(client_fd);
                        continue;
                }
                ctx->client_fd   = client_fd;
                ctx->client_port = ntohs(ca.sin_port);
                ctx->rt          = &rt;
                inet_ntop(AF_INET, &ca.sin_addr,
                          ctx->client_ip, sizeof(ctx->client_ip));

                pthread_t tid;
                if (pthread_create(&tid, NULL, client_thread, ctx) != 0) {
                        log_error("pthread_create failed");
                        close(client_fd);
                        free(ctx);
                        continue;
                }
                pthread_detach(tid);
        }

        room_table_destroy(&rt);
        close(server_fd);
        return 0;
}
