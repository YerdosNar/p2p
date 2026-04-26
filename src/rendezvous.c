#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../include/typedefs.h"

#define DEFAULT_PORT    8888
#define LISTEN_BACKLOG  128

static i32 init_listen_fd(u16 port) {
        i32 fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) {
                perror("socket");
                return -1;
        }

        i32 opt = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
                perror("setsockopt(SO_REUSEADDR)");
                close(fd);
                return -1;
        }

        struct sockaddr_in sa = {0};
        sa.sin_family   = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        sa.sin_port = htons(port);

        if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
                perror("bind");
                close(fd);
                return 1;
        }

        if (listen(fd, LISTEN_BACKLOG) == -1) {
                perror("listen");
                close(fd);
                return 1;
        }

        return fd;
}

static void usage(const char *exe)
{
        printf("Usage: %s [options]\n\n", exe);
        printf("Options:\n");
        printf("  -p, --port <port>             Listening port (default=%d)\n",
                DEFAULT_PORT);
        printf("  -h, --help                    Show this help message\n\n" );
        printf("Example:\n");
        printf("  %s -p 1234\n", exe);
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
                                fprintf(stderr, "WARN: %s flag needs a numeric value; using %d\n",
                                        argv[i], DEFAULT_PORT);
                                continue;
                        }
                        int p = atoi(argv[++i]);
                        if (p <= 0 || p > 65535) {
                                fprintf(stderr, "WARN: invalid port '%s'; using %d\n",
                                        argv[i], DEFAULT_PORT);
                                continue;
                        }
                        port = (u16)p;
                }
                else {
                        fprintf(stderr, "WARN: Unknown argument: %s\n", argv[i]);
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

        printf("RENDEZVOUS listening on port: %d.\n", port);

        for (;;) {
                struct sockaddr_in ca;
                socklen_t ca_len = sizeof(ca);

                i32 client_fd = accept(server_fd, (struct sockaddr *)&ca, &ca_len);

                if (client_fd == -1) {
                        perror("accept");
                        continue;
                }

                printf("* Connection from %s:%u\n",
                                inet_ntoa(ca.sin_addr),
                                ntohs(ca.sin_port));
                close(client_fd);
        }

        return 0;
}
