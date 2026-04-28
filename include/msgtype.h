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
} MsgType;

#endif
