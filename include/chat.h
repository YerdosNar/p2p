#ifndef CHAT_H
#define CHAT_H

#include "crypto.h"
#include "typedefs.h"

/*
 * chat.h - bidirectional chat loop over an established P2P session.
 *
 * Spawns a recv thread; the calling thread becomes the send thead.
 * Returns when either side ends the convesation (/quit, peer
 * disconnect, EOF on stdin).
 *
 * Threading model:
 *      - send thread (caller): reads stdin char-by-char, echoes,
 *        sends complete lines as MSG_CHAT
 *      - recv thread: blocks on crypto_recv_typed, prints to stdout
 *
 * The crypto session's tx state is owned by the send thread; rx
 * state by the recv thread. A second sender (e.g. a hearbeat thread)
 *
 * This function never returns normally; it exit()s the process when
 * the chat ends. Termios is restored before exit, including on SIGINT/SIGTERM.
 */
void chat_run(i32 fd, CryptoSession *session, const char *peer_fp);

#endif
