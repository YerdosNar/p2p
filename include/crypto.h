#ifndef CRYPTO_H
#define CRYPTO_H

#include "typedefs.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sodium.h>

/*
 * crytpo.h - E2EE layer.
 *
 * Key exchagne : X25519 via crypto_kx_*
 * Transport    : crypto_secretstream_xchacha20poly1305
 *
 * The session own a pair of secretstream states: one for outgoing
 * message (tx) and one for incoming (rx). Both states are seeded
 * from a 32-byte symmetric key derived from the X25519 exchange.
 *
 * Wire format (per message, all values network-byte-order where applicable):
 *
 *   [ length: u32, 4 bytes ] cipher length
 *   [ ciphertext: length   ] secretstream output (= plaintext_len + 17)
 *
 * Plaintext layout (after secretstream decryption):
 *
 *   [ type: u8, 1 byte ] MsgType
 *   [ payload: ...     ] type-specific
 *
 * Hard limit on length: CRYPTO_MAX_FRAME (1MiB). A peer that
 * announces a larger frame is dropped immediately - no allocation,
 * no decryption attempt.
 */
#define CRYPTO_MAX_FRAME (1u * MB)

#define CRYPTO_HDR_BYTES crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define CRYPTO_TAG_BYTES crypto_secretstream_xchacha20poly1305_ABYTES
#define CRYPTO_KEY_BYTES crypto_secretstream_xchacha20poly1305_KEYBYTES

#define CRYPTO_PUBKEYB crypto_kx_PUBLICKEYBYTES
#define CRYPTO_SECKEYB crypto_kx_SECRETKEYBYTES

typedef struct {
        crypto_secretstream_xchacha20poly1305_state tx;
        crypto_secretstream_xchacha20poly1305_state rx;
        u8 last_rx_tag;
} CryptoSession;

/*
 * Transfer-stream send/recv. Used for streaming a single file via a
 * dedicated secretstream that gets created at the start of a transfer
 * and discard at the end (TAG_FINAL).
 *
 * The transfer stream's wire format is the same length-prefix + AEAD
 * frame as the control stream, but plaintext has no type byte (the
 * receiver knows it's expecting file data).
 *
 * State for the transfer stream is per-direction; sender holds tx,
 * receiver hols rx. Allocated them on the stack at transfer start
 * and zero them on completion.
 */
typedef struct {
        crypto_secretstream_xchacha20poly1305_state state;
} XferStreamTx;

typedef struct {
        crypto_secretstream_xchacha20poly1305_state state;
        u8 last_tag;
} XferStreamRx;

#define XFER_KEY_BYTES  CRYPTO_KEY_BYTES
#define XFER_HDR_BYTES  CRYPTO_HDR_BYTES
#define XFER_MAX_CHUNK  (64u * KB)

/*
 * Initialize a sender stream: generate fresh key, init push, return
 * the header to send. Caller stores key + header in the
 * MSG_TRANSFER_HEADER payload (key first, then header).
 *
 * Return true on success.
 */
bool crypto_xfer_init_sender(XferStreamTx *out,
                             u8 key[XFER_KEY_BYTES],
                             u8 hdr[XFER_HDR_BYTES]);

/*
 * Initialize a receiver stream from a key + header received over the
 * control channel. Returns true on success.
 */
bool crypto_xfer_init_receiver(XferStreamRx *out,
                               const u8 key[XFER_KEY_BYTES],
                               const u8 hdr[XFER_HDR_BYTES]);

/*
 * Send one chunk on the transfer stream. tag is TAG_MESSAGE for
 * normal chunks, TAG_FINAL for the last one.
 *
 * Frames the chunk with a 4-byte length prefix, same as control stream.
 */
bool crypto_xfer_send_chunk(i32 fd, XferStreamTx *s,
                            const u8 *data, u32 len,
                            u8 tag);

/*
 * Receive one chunk. Allocates a heap buffer for the plaintext (Caller
 * frees).
 *
 * On success: *out_len is the chunk size, and s->last_tag is set to
 *              TAG_MESSAGE or TAG_FINAL.
 * On failure: return false
 *
 * Failure reasons: framing error, oversized frame, or AEAD failure.
 */
bool crypto_xfer_recv_chunk(i32, XferStreamRx *s,
                            u8 **out_data, u32 *out_len);

void crypto_xfer_close(void *stream); // Zeroes either tx or rx state

/*
 * Run the full handshake on an already-connected socket.
 *
 * Both peers call this. Roles (client/server in the kx sense) are
 * decided automatically by lexigraphic pulic-key comparison, so
 * neither side needs to know in advance.
 *
 * On success: fills *out and returns true.
 * On failure: zeroes any partial state in *out and returns false.
 *             The caller should close fd; the handshake leaves no
 *             usable session behind.
 */
bool crypto_session_handshake(i32 fd, CryptoSession *out);

/*
 * Like crypto_session_handshake, but also binds the long-lived
 * keypair into the derivation. The peer's long-lived pubkey must
 * be known in advance (typically learned through the rendezvous)
 *
 * If the connected party is not the holder of peer_long_pk's
 * secret key, the derived session keys won't match and the first
 * recv will fail with a decryption error.
 *
 * Returns true on a successful handshake. The caller still needs
 * to do at least one recv (e.g., a known-plaintext "hello") to
 * confirm authentication actually held - the kx_session_keys
 * call itself doesn't fail on a wrong long_pk; the divergence
 * shows up at decrypt time.
 */
bool crypto_session_handshake_authenticated(
                i32           fd,
                const u8      my_long_pk[CRYPTO_PUBKEYB],
                const u8      my_long_sk[CRYPTO_SECKEYB],
                const u8      peer_long_pk[CRYPTO_PUBKEYB],
                CryptoSession *out);

/*
 * Encrypt and send one typed message.
 *
 * 'data' may be NULL when 'len' == 0 (for empty-payload message).
 * 'len' must be <=CRYPTO_MAX_FRAME - CRYPTO_TAG_BYTES - 1 (room for
 * tag and type byte).
 *
 * Returns true if the entire frame reached the kernel (net_send_all).
 */
bool crypto_send_typed(i32 fd, u8 type,
                       const u8 *data, u32 len,
                       CryptoSession *s);

/*
 * Receive and decrypt one typed message.
 *
 * On success:
 *   *out_type = type byte
 *   *otu_data = heap buffer with payload (caller must free)
 *               always NUL-terminated past the payload, so MSG_CHAT
 *               payloads can be cast to (char *) directly
 *   *out_len  = payload length, NOT including the type byte or the NUL
 *
 * On failure: return false; *out_data is untouched.
 *
 * Failures include: short read, oversized frame, decryption error,
 * peer-initiated stream end (TAG_FINAL on the control stream is a
 * protocol error - the control stream lives until the connection
 * closes).
 */
bool crypto_recv_typed(i32 fd,
                      u8 *out_type,
                      u8 **out_data,
                      u32 *out_len,
                      CryptoSession *s);

/*
 * Zero all key material in *s. Safe to call on a partially-initialized
 * session (e.g. after a failed handshake).
 */
void crypto_session_close(CryptoSession *s);

#endif
