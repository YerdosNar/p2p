#ifndef MSGTYPE_H
#define MSGTYPE_H

#include <stdint.h>

/*
 * Message types carries in the first byte of every plaintext.
 *
 * Authenticated by the AEAD because they're inside the ciphertext.
 * A peer that flips a type byte will fail decryption, not silently
 * route a chat message through the file path.
 *
 * 0x00 is reserved (never sent) so an all-zero plaintext is invalid
 * and stands out in debugging.
 */
typedef enum {
        MSG_RESERVED    = 0x00,
        MSG_CHAT        = 0x01,

        PROTO_ROLE_REQ  = 0x10,
        PROTO_ROLE_RES  = 0x11,
        PROTO_ROOM_ID   = 0x12,
        PROTO_PEER_INFO = 0x13,
        PROTO_ERROR     = 0x14,
        PROTO_PUBKEY    = 0x15,
} MsgType;

/*
 * PROTO_PEER_INFO payload:
 *
 *   [ ip_len: 1 byte                       ]
 *   [ ip:     ip_len bytes (ASCII, no NUL) ]
 *   [ port:   2 bytes, network order       ]
 *   [pubkey:  crypto_kx_PUBLICKEYBYTES (32)]
 *
 * Total: 1 + ip_len + 2 + 32 bytes.
 *
 * ip is human-readable ("192.168.1.5", "10.0.0.1"). Length-prefixed
 * because IPv6 may be implemented later; keeping it variable makes
 * that a non-breaking change.
 */

#endif
