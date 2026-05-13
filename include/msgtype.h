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
        MSG_RESERVED            = 0x00,
        MSG_CHAT                = 0x01,
        MSG_BYE                 = 0x02,
        MSG_NAME                = 0x03,
        MSG_MODE                = 0x04,

        PROTO_ROLE_REQ          = 0x10,
        PROTO_ROLE_RES          = 0x11,
        PROTO_ROOM_ID           = 0x12,
        PROTO_PEER_INFO         = 0x13,
        PROTO_ERROR             = 0x14,
        PROTO_WARN              = 0x15,
        PROTO_PUBKEY            = 0x16,
        PROTO_ROOM_PASSWORD     = 0x17,

        MSG_FILE_OFFER          = 0x20,
        MSG_FILE_ACCEPT         = 0x21,
        MSG_FILE_REJECT         = 0x22,
        MSG_TRANSFER_HDR        = 0x23,
        MSG_TRANSFER_DONE       = 0x24,

        MSG_PROXY_OPEN          = 0x30,
        MSG_PROXY_OPEN_OK       = 0x31,
        MSG_PROXY_OPEN_FAIL     = 0x32,
        MSG_PROXY_DATA          = 0x33,
        MSG_PROXY_CLOSE         = 0x34,
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

/*
 * Proxy mode payloads (joiner-initiated SOCKS5 tunneling).
 * Stream IDs are u32, allocated by the joiner, monotonic per session.
 *
 * MSG_PROXY_OPEN (joiner -> host):
 *   [ stream_id: u32   ]
 *   [ port:      u16   ]
 *   [ host_len:  u8    ]   1..255
 *   [ host:      host_len bytes, ASCII, no NUL ]
 *
 * MSG_PROXY_OPEN_OK (host -> joiner):
 *   [ stream_id: u32   ]
 *
 * MSG_PROXY_OPEN_FAIL (host -> joiner):
 *   [ stream_id:  u32  ]
 *   [ reason_len: u8   ]
 *   [ reason:     reason_len bytes, ASCII ]
 *
 * MSG_PROXY_DATA (either direction):
 *   [ stream_id: u32   ]
 *   [ data_len:  u16   ]   1..32768; zero-length is invalid
 *   [ data:      data_len bytes ]
 *
 * MSG_PROXY_CLOSE (either direction, half-close):
 *   [ stream_id: u32   ]
 *
 * After CLOSE from side X, side X sends no more DATA on that stream.
 * The other side may keep sending until it also CLOSEs. Stream is
 * reaped when both halves are closed.
 */

#endif
