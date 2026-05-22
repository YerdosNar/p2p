#ifndef HOLEPUNCH_H
#define HOLEPUNCH_H

/*
 * Close rendezvous_fd, then race a listen+accept against a connect
 * on the same local port toward (peer_ip, peer_port).
 *
 * 'peer_family' is 4 or 6.
 * 'rendezvous_family' is the family the rendezvous_fd is in.
 * If they don't match, we can't do proper hole-punch.
 *
 * Returns the connected fd on success (in blocking mode), -1 on
 * timeout or failure.
 */

#include "typedefs.h"

int holepunch_to_peer(i32        rendezvous_fd,
                      const char *peer_ip,
                      u16        peer_port,
                      u8         peer_family,
                      u8         rendezvous_family);

#endif /* HOLEPUNCH_H */
