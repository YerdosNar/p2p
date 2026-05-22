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
 * Get domain name and get IPv4 address
 *
 * out_ip must point to at least INET_ADDRSTRLEN bytes.
 * On success: writes a NUL-terminated dotted-quad string, returns true.
 * On failure: (NXDOMAIN, no IPv4 records, lookup error): logs and returns false.
 */
bool net_resolve_domain(const char *domain, char *out_ip);

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
 * 'local_addr' may be either struct sockaddr_in (AF_INET) or struct
 * sockaddr_in6 (AF_INET6), 'addr_len' is the appropriate sizeof for the
 * concrete struct. The socket's family is taken from local_addr->sa_family.
 *
 * On success: return fd.
 * On failure: log the cause, and return -1.
 */
int net_make_bound_socket(const struct sockaddr *local_addr,
                          socklen_t addr_len);

/*
 * Replace the first '\r' or '\n' in str with '\0'. No-op if neither
 * is present. Useful for cleaning fgets() output.
 */
void net_strip_newline(char *str);

#endif
