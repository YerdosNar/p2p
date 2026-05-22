#include "../include/holepunch.h"
#include "../include/net.h"
#include "../include/logger.h"

#include <stdio.h>
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
 * Fill *out with a sockaddr_storage bound to the wildcard address
 * of 'family' (4 or 6) on local_port. Returns the address length.
 */
static socklen_t make_local_addr(struct sockaddr_storage *out,
                                 u8 family, u16 local_port)
{
        memset(out, 0, sizeof(*out));
        if (family == 4) {
                struct sockaddr_in *sa = (struct sockaddr_in *)out;
                sa->sin_family      = AF_INET;
                sa->sin_addr.s_addr = htonl(INADDR_ANY);
                sa->sin_port        = htons(local_port);
                return sizeof(*sa);
        } else {
                struct sockaddr_in6 *sa = (struct sockaddr_in6 *)out;
                sa->sin6_family = AF_INET6;
                sa->sin6_addr   = in6addr_any;
                sa->sin6_port   = htons(local_port);
                return sizeof(*sa);
        }
}

/*
 * Fill *out with a sockaddr_storage pointing to (peer_ip, peer_port)
 * in 'family' (4 or 6). Returns the address length, or 0 on parse
 * failure.
 */
static socklen_t make_peer_addr(struct sockaddr_storage *out,
                                u8 family,
                                const char *peer_ip, u16 peer_port)
{
        memset(out, 0, sizeof(*out));
        if (family == 4) {
                struct sockaddr_in *sa = (struct sockaddr_in *)out;
                sa->sin_family = AF_INET;
                sa->sin_port   = htons(peer_port);
                if (inet_pton(AF_INET, peer_ip, &sa->sin_addr) != 1) {
                        log_error("Bad IPv4 peer address: %s", peer_ip);
                        return 0;
                }
                return sizeof(*sa);
        } else {
                struct sockaddr_in6 *sa = (struct sockaddr_in6 *)out;
                sa->sin6_family = AF_INET6;
                sa->sin6_port   = htons(peer_port);
                if (inet_pton(AF_INET6, peer_ip, &sa->sin6_addr) != 1) {
                        log_error("Bad IPv6 peer address: %s", peer_ip);
                        return 0;
                }
                return sizeof(*sa);
        }
}

static int open_listen(u8 family, u16 local_port)
{
        struct sockaddr_storage sa;
        socklen_t salen = make_local_addr(&sa, family, local_port);

        int fd = net_make_bound_socket((const struct sockaddr *)&sa, salen);
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

static int open_connect(u8 family, u16 local_port,
                        const char *peer_ip, u16 peer_port)
{
        struct sockaddr_storage local_sa;
        socklen_t local_salen = make_local_addr(&local_sa, family, local_port);

        int fd = net_make_bound_socket(
                        (const struct sockaddr *)&local_sa, local_salen);
        if (fd == -1) return -1;
        if (!set_nonblocking(fd)) {
                close(fd);
                return -1;
        }

        struct sockaddr_storage peer_sa;
        socklen_t peer_salen = make_peer_addr(&peer_sa, family,
                                              peer_ip, peer_port);
        if (peer_salen == 0) {
                close(fd);
                return -1;
        }

        int rc = connect(fd, (const struct sockaddr *)&peer_sa, peer_salen);
        if (rc == 0) return fd;
        if (errno == EINPROGRESS) return fd;

        log_warn("connect() immediately failed: %s", strerror(errno));
        close(fd);
        return -1;
}

/*
 * Stringify a sockaddr_storage's IP and port for logging.
 */
static void format_addr(const struct sockaddr_storage *sa,
                        char *out_ip, size_t out_size, u16 *out_port)
{
        if (sa->ss_family == AF_INET) {
                const struct sockaddr_in *s = (const struct sockaddr_in *)sa;
                inet_ntop(AF_INET, &s->sin_addr, out_ip, out_size);
                *out_port = ntohs(s->sin_port);
        } else if (sa->ss_family == AF_INET6) {
                const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)sa;
                inet_ntop(AF_INET6, &s->sin6_addr, out_ip, out_size);
                *out_port = ntohs(s->sin6_port);
        } else {
                snprintf(out_ip, out_size, "?");
                *out_port = 0;
        }
}

int holepunch_to_peer(i32 rendezvous_fd,
                      const char *peer_ip, u16 peer_port,
                      u8 peer_family, u8 rendezvous_family)
{
        u16 local_port = 0;

        if (peer_family == rendezvous_family) {
                /* Same family: reuse the rendezvous fd's local port so
                 * the NAT mapping we already established can be used
                 * for the peer-to-peer connection. */
                struct sockaddr_storage local;
                socklen_t llen = sizeof(local);
                if (getsockname(rendezvous_fd,
                                (struct sockaddr *)&local, &llen) == -1) {
                        log_error("getsockname(): %s", strerror(errno));
                        return -1;
                }
                if (local.ss_family == AF_INET) {
                        local_port = ntohs(((struct sockaddr_in *)&local)->sin_port);
                } else {
                        local_port = ntohs(((struct sockaddr_in6 *)&local)->sin6_port);
                }
                log_debug("Local port for hole-punch: %u (IPv%u)",
                          local_port, peer_family);
        } else {
                /* Mixed families: the NAT mapping in our rendezvous family
                 * is useless for dialing the peer in the other family.
                 * Bind to an ephemeral port (kernel choice) and just try
                 * a direct connect. Works iff our network has direct
                 * reachability to the peer (unusual in this scenario). */
                log_warn("Mixed family: rendezvous IPv%u, peer IPv%u. "
                         "True hole-punch not possible; attempting plain dial.",
                         rendezvous_family, peer_family);
                local_port = 0;
        }

        close(rendezvous_fd);

        int listen_fd  = open_listen(peer_family, local_port);
        if (listen_fd < 0) return -1;

        int connect_fd = open_connect(peer_family, local_port,
                                      peer_ip, peer_port);
        if (connect_fd < 0) {
                close(listen_fd);
                return -1;
        }

        log_info("Hole-punching to %s:%u (local port %u, IPv%u)...",
                 peer_ip, peer_port, local_port, peer_family);

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
                if (rc == 0) break;

                if (fds[0].revents & POLLIN) {
                        struct sockaddr_storage ca;
                        socklen_t cl = sizeof(ca);
                        int accepted = accept(listen_fd,
                                              (struct sockaddr *)&ca, &cl);
                        if (accepted >= 0) {
                                char ipstr[INET6_ADDRSTRLEN] = {0};
                                u16 port;
                                format_addr(&ca, ipstr, sizeof(ipstr), &port);
                                log_info("Inbound connection accepted from %s:%u",
                                         ipstr, port);
                                winner = accepted;
                                break;
                        }
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                                log_warn("accept(): %s", strerror(errno));
                        }
                }

                if (fds[1].revents & (POLLOUT | POLLERR | POLLHUP)) {
                        int err = 0;
                        socklen_t elen = sizeof(err);
                        if (getsockopt(connect_fd, SOL_SOCKET, SO_ERROR,
                                       &err, &elen) == 0 && err == 0) {
                                log_info("Outbound connection succeeded.");
                                winner = connect_fd;
                                connect_fd = -1;
                                break;
                        }
                        log_debug("connect() pending: %s", strerror(err));
                        fds[1].fd = -1;
                        close(connect_fd);
                        connect_fd = -1;
                }
        }

        if (winner != listen_fd && listen_fd >= 0) close(listen_fd);
        if (winner != connect_fd && connect_fd >= 0) close(connect_fd);

        if (winner < 0) {
                log_error("Hole-punch timed out after %d ms",
                          HOLEPUNCH_TIMEOUT_MS);
                return -1;
        }

        if (!set_blocking(winner)) {
                log_warn("Couldn't restore blocking mode on winning fd");
        }
        return winner;
}
