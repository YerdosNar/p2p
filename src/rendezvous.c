#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../include/typedefs.h"
#include "../include/logger.h"

#define DEFAULT_PORT    8888
#define LISTEN_BACKLOG  128

static i32 init_listen_fd(u16 port) {
        i32 fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) {
                log_error("socket: %s", strerror(errno));
                return -1;
        }

        i32 opt = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
                log_error("setsockopt(SO_REUSEADDR): %s", strerror(errno));
                goto fail;
        }

        struct sockaddr_in sa = {0};
        sa.sin_family   = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        sa.sin_port = htons(port);

        if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
                log_error("bind(): %s", strerror(errno));
                goto fail;
        }

        if (listen(fd, LISTEN_BACKLOG) == -1) {
                perror("listen");
                goto fail;
        }

        return fd;
fail:
        close(fd);
        return -1;
}

static void usage(const char *exe)
{
        printf("Usage: %s [options]\n\n", exe);
        printf("Options:\n");
        printf("  -p, --port <port>             Listening port (default=%d)\n",
                DEFAULT_PORT);
        printf("  -L, --log-level <level>       error|warn|info|debug (default=info)\n");
        printf("  -h, --help                    Show this help message\n\n");
        printf("Example:\n  %s -p 1234 -L debug\n", exe);
}

static u16 parse_args(int argc, char **argv)
{
        u16 port = DEFAULT_PORT;

        for (int i = 1; i < argc; i++) {
                if (!strncmp(argv[i], "-h", 2) || !strncmp(argv[i], "--help", 6)) {
                        usage(argv[0]);
                        exit(EXIT_SUCCESS);
                }
                if (!strncmp(argv[i], "-p", 2) || !strncmp(argv[i], "--port", 6)) {
                        if (i + 1 >= argc) {
                                log_warn("'%s' flag needs a numeric value; using %d\n",
                                        argv[i], DEFAULT_PORT);
                                continue;
                        }
                        int p = atoi(argv[++i]);
                        if (p <= 0 || p > 65535) {
                                log_warn("invalid port '%s'; using %d\n",
                                        argv[i], DEFAULT_PORT);
                                continue;
                        }
                        port = (u16)p;
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
                        }
                        logger_set_level(lvl);
                }
                else {
                        log_error("Unknown argument: %s", argv[i]);
                        usage(argv[0]);
                        exit(EXIT_FAILURE);
                }
        }

        return port;
}

int main(int argc, char **argv)
{
        u16 port = parse_args(argc, argv);
        i32 server_fd = init_listen_fd(port);
        if (server_fd == -1) return 1;

        log_info("Rendezvous listening on port: %u.", port);

        for (;;) {
                struct sockaddr_in ca;
                socklen_t ca_len = sizeof(ca);

                i32 client_fd = accept(server_fd,
                                (struct sockaddr *)&ca, &ca_len);

                if (client_fd == -1) {
                        log_warn("accept(): %s", strerror(errno));
                        continue;
                }

                log_info("Connection from %s:%u",
                                inet_ntoa(ca.sin_addr),
                                ntohs(ca.sin_port));
                log_debug("Closing client_fd=%d immediately.", client_fd);
                close(client_fd);
        }

        close(server_fd);
        return 0;
}
