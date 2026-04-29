#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <netinet/in.h>

#include "crypto.h"
#include "typedefs.h"
#include "room.h"

/*
 * protocol.h - the rendezvous server's per-client state machine.
 *
 * Called by rendezvous.c after the per-client thread has done the
 * crypto handshake. The protocol owns the conversation from "ask
 * for role" through "match mode", and is the only thing that  calls
 * into room.c
 *
 * On entry:
 *      client_fd: connected, encrypted with *session
 *      client_ip / client_port: peer's address as seen by the server
 *      rt: the shared room table
 *
 * The function returns when the conversation is complete (either
 * matched, errored, or the peer disconnected). It does NOT close
 * client_fd in the matched-host case - that fd is now owned by the
 * room table and will be closed by the joiner thread.
 */
void protocol_handle_client(
                i32             client_fd,
                const char      *client_ip,
                u16             client_port,
                CryptoSession   *session,
                RoomTable       *rt);

#endif
