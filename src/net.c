#define _GNU_SOURCE

#include "../include/net.h"
#include "../include/logger.h"
#include "../include/typedefs.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

bool net_recv_all(int fd, void *buf, size_t len)
{
        size_t total = 0;
        u8 *p = (u8 *)buf;

        while (total < len) {
                ssize_t read = recv(fd, p + total, len - total, 0);
                if (read > 0) {
                        total += (size_t)read;
                        continue;
                }
                if (read == 0) {
                        log_debug("net_recv_all: peer closed after %zu/%zu bytes.",
                                        total, len);
                        return false;
                }
                if (errno == EINTR) continue;
                log_warn("net_recv_all: recv() failed: %s", strerror(errno));
                return false;
        }
        return true;
}

bool net_send_all(int fd, const void *buf, size_t len)
{
        size_t total = 0;
        const u8 *p = (const u8 *)buf;

#ifdef MSG_NOSIGNAL
        const int flags = MSG_NOSIGNAL;
#else
        const int flags = 0;
#endif

        while (total < len) {
                ssize_t written = send(fd, p + total, len - total, flags);
                if (written > 0) {
                        total += (size_t)written;
                        continue;
                }
                if (written < 0 && errno == EINTR) continue;
                log_warn("net_send_all: send() failed: %s",
                                strerror(written < 0 ? errno : 0));
                return false;
        }
        return true;
}

int net_make_bound_socket(const struct sockaddr_in *local_addr)
{
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) {
                log_error("socket(): %s", strerror(errno));
                return -1;
        }

        int opt = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                                &opt, sizeof(opt)) == -1) {
                log_error("setsockopt(SO_REUSEADDR): %s", strerror(errno));
                close(fd);
                return -1;
        }

#ifdef SO_REUSEPORT
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
                                &opt, sizeof(opt)) == -1) {
                log_warn("setsockopt(SO_REUSEPORT): %s", strerror(errno));
        }
#endif

        if (bind(fd, (const struct sockaddr *)local_addr,
                                sizeof(*local_addr)) == -1) {
                log_error("bind(): %s", strerror(errno));
                close(fd);
                return -1;
        }

        return fd;
}

void net_strip_newline(char *str)
{
        if (!str) return;
        str[strcspn(str, "\r\n")] = '\0';
}
