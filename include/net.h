#ifndef NET_H
#define NET_H

#include "typedefs.h"

#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>
/*
 * net.h - low-level socket helpers shared by peer and rendezvous.
 *
 * Nothing in here knows about crypto or framing. These are the
 * "plumbing" calls: read N bytes, write N bytes, make a bound socket.
 * Higher layers (crypto, fileproto) compose them.
 */

/*
 * Receive exactly 'len' bytes into 'buf', looping over short reads.
 *
 * Returns true if the full buffer was filled.
 * Returns false on EOF (peer closed) or any unrecoverable recv() error.
 * EINTR is retried automatically.
 */
bool net_recv_all(int fd, void *buf, size_t len);

/*
 * Send exactly 'len' bytes from 'buf', looping over short writes.
 *
 * Returns true if the full buffer was send.
 * Returns false on any unrecoverable send() error.
 * EINTR is retried automatically.
 */
bool net_send_all(int fd, const void *buf, size_t len);

/*
 * Create a TCP socket bound to *local_addr with SO_REUSEADDR + SO_REUSEPORT.
 *
 * SO_REUSEPORT is essential for the peer side: hole-punching reuses the same local port for the rendezvous connection and the inbound P2P
 * connection from the other peer. The rendezvous side technically only
 * needs SO_REUSEADDR, but set both for symmetry.
 *
 * Returns the fd on success, or -1 on failure (with the cause logged).
 */
int net_make_bound_socket(const struct sockaddr_in *local_addr);

/*
 * Replace the first '\r' or '\n' in str with '\0'. No-op if neither
 * is present. Useful for cleaning fgets() output.
 */
void net_strip_newline(char *str);

#endif
