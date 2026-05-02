#include "../include/holepunch.h"
#include "../include/net.h"
#include "../include/logger.h"

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define HOLEPUNCH_TIMEOUT_MS 10000   /* 10s total */

static bool set_nonblocking(int fd)
{
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) return false;
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static bool set_blocking(int fd)
{
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) return false;
        return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == 0;
}

/*
 * Make a listen socket bound to the given local port (with SO_REUSEPORT).
 * Sets non-blocking. Returns fd or -1.
 */
static int open_listen(uint16_t local_port)
{
        struct sockaddr_in sa = {0};
        sa.sin_family      = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        sa.sin_port        = htons(local_port);

        int fd = net_make_bound_socket(&sa);
        if (fd == -1) return -1;
        if (listen(fd, 1) == -1) {
                log_error("listen(): %s", strerror(errno));
                close(fd);
                return -1;
        }
        if (!set_nonblocking(fd)) {
                log_error("fcntl set non-blocking on listen fd");
                close(fd);
                return -1;
        }
        return fd;
}

/*
 * Make a connect socket bound to the given local port, attempting
 * connect() in non-blocking mode. Will typically return EINPROGRESS;
 * caller polls for writability to detect completion.
 */
static int open_connect(uint16_t local_port,
                        const char *peer_ip, uint16_t peer_port)
{
        struct sockaddr_in sa = {0};
        sa.sin_family      = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        sa.sin_port        = htons(local_port);

        int fd = net_make_bound_socket(&sa);
        if (fd == -1) return -1;
        if (!set_nonblocking(fd)) {
                close(fd);
                return -1;
        }

        struct sockaddr_in peer = {0};
        peer.sin_family = AF_INET;
        peer.sin_port   = htons(peer_port);
        if (inet_pton(AF_INET, peer_ip, &peer.sin_addr) != 1) {
                log_error("Bad peer IP: %s", peer_ip);
                close(fd);
                return -1;
        }

        int rc = connect(fd, (struct sockaddr *)&peer, sizeof(peer));
        if (rc == 0) return fd;            /* connect already succeeded */
        if (errno == EINPROGRESS) return fd;  /* will resolve via poll */

        log_warn("connect() immediately failed: %s", strerror(errno));
        close(fd);
        return -1;
}

int holepunch_to_peer(int rendezvous_fd,
                      const char *peer_ip, uint16_t peer_port)
{
        /* 1. Learn our local port from the rendezvous socket. */
        struct sockaddr_in local;
        socklen_t llen = sizeof(local);
        if (getsockname(rendezvous_fd,
                        (struct sockaddr *)&local, &llen) == -1) {
                log_error("getsockname(): %s", strerror(errno));
                return -1;
        }
        uint16_t local_port = ntohs(local.sin_port);
        log_debug("Local port for hole-punch: %u", local_port);

        /*
         * 2. Close rendezvous fd. We need its port back for the new
         *    sockets. SO_REUSEPORT makes this safe even though the
         *    kernel may not have fully released the binding yet.
         */
        close(rendezvous_fd);

        /* 3. Open listen + connect sockets. */
        int listen_fd  = open_listen(local_port);
        if (listen_fd < 0) return -1;

        int connect_fd = open_connect(local_port, peer_ip, peer_port);
        if (connect_fd < 0) {
                close(listen_fd);
                return -1;
        }

        log_info("Hole-punching to %s:%u (local port %u)...",
                 peer_ip, peer_port, local_port);

        /* 4. Poll until one wins or timeout. */
        struct pollfd fds[2] = {
                { .fd = listen_fd,  .events = POLLIN  },
                { .fd = connect_fd, .events = POLLOUT },
        };

        int winner = -1;
        int remaining_ms = HOLEPUNCH_TIMEOUT_MS;

        while (winner == -1 && remaining_ms > 0) {
                int rc = poll(fds, 2, remaining_ms);
                if (rc < 0) {
                        if (errno == EINTR) continue;
                        log_error("poll(): %s", strerror(errno));
                        break;
                }
                if (rc == 0) break;     /* timeout */

                /* Listen side: an inbound connection is ready to accept. */
                if (fds[0].revents & POLLIN) {
                        struct sockaddr_in ca; socklen_t cl = sizeof(ca);
                        int accepted = accept(listen_fd,
                                              (struct sockaddr *)&ca, &cl);
                        if (accepted >= 0) {
                                log_info("Inbound connection accepted from %s:%u",
                                         inet_ntoa(ca.sin_addr),
                                         ntohs(ca.sin_port));
                                winner = accepted;
                                break;
                        }
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                                log_warn("accept(): %s", strerror(errno));
                        }
                        /* Otherwise spurious wakeup; keep polling. */
                }

                /* Connect side: socket is writable, check actual outcome. */
                if (fds[1].revents & (POLLOUT | POLLERR | POLLHUP)) {
                        int err = 0;
                        socklen_t elen = sizeof(err);
                        if (getsockopt(connect_fd, SOL_SOCKET, SO_ERROR,
                                       &err, &elen) == 0 && err == 0) {
                                log_info("Outbound connection succeeded.");
                                winner = connect_fd;
                                connect_fd = -1;   /* don't close below */
                                break;
                        }
                        log_debug("connect() pending: %s", strerror(err));
                        /*
                         * Connect failed (likely peer not yet listening).
                         * Stop watching connect_fd; keep watching listen_fd
                         * in case the peer's inbound shows up.
                         */
                        fds[1].fd = -1;   /* poll ignores negative fds */
                        close(connect_fd);
                        connect_fd = -1;
                }
        }

        /* 5. Cleanup losers. */
        if (winner != listen_fd && listen_fd >= 0) close(listen_fd);
        if (winner != connect_fd && connect_fd >= 0) close(connect_fd);

        if (winner < 0) {
                log_error("Hole-punch timed out after %d ms",
                          HOLEPUNCH_TIMEOUT_MS);
                return -1;
        }

        /* 6. Return to blocking I/O for the rest of the program. */
        if (!set_blocking(winner)) {
                log_warn("Couldn't restore blocking mode on winning fd");
        }
        return winner;
}
