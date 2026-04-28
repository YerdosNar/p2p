#include "../include/crypto.h"
#include "../include/net.h"
#include "../include/logger.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static bool derive_shared_key(const u8 my_pk[CRYPTO_PUBKEYB],
                              const u8 my_sk[CRYPTO_SECKEYB],
                              const u8 pr_pk[CRYPTO_PUBKEYB],
                              u8 key_out[CRYPTO_KEY_BYTES])
{
        int cmp = memcmp(my_pk, pr_pk, CRYPTO_PUBKEYB);
        if (cmp == 0) {
                log_error("Public keys are identical (loopback or broken RNG).");
                return false;
        }

        u8 rx[crypto_kx_SESSIONKEYBYTES];
        u8 tx[crypto_kx_SESSIONKEYBYTES];

        int rc;
        if (cmp < 0) {
                rc = crypto_kx_client_session_keys(rx, tx, my_pk, my_sk, pr_pk);
                log_debug("kx role: CLIENT");
        } else {
                rc = crypto_kx_server_session_keys(rx, tx, my_pk, my_sk, pr_pk);
                log_debug("kx role: SERVER");
        }
        if (rc != 0) {
                log_error("crypto_kx_*_session_keys failed.");
                sodium_memzero(rx, sizeof(rx));
                sodium_memzero(tx, sizeof(tx));
                return false;
        }

        /*
         * To get a single shared key, hash rx || tx in canonical
         * (sorted) order: smaller half first, larger second. This makes
         * the hash input identical on both sides regardless of role.
         */
        const u8 *first  = (memcmp(rx, tx, sizeof(rx)) < 0) ? rx : tx;
        const u8 *second = (first == rx) ? tx : rx;

        crypto_generichash_state h;
        crypto_generichash_init(&h, NULL, 0,  CRYPTO_KEY_BYTES);
        crypto_generichash_update(&h, first,  crypto_kx_SESSIONKEYBYTES);
        crypto_generichash_update(&h, second, crypto_kx_SESSIONKEYBYTES);
        crypto_generichash_final(&h, key_out, CRYPTO_KEY_BYTES);

        sodium_memzero(rx, sizeof(rx));
        sodium_memzero(tx, sizeof(tx));
        return true;
}

bool crypto_session_handshake(i32 fd, CryptoSession *out)
{
        if (sodium_init() < 0) {
                log_error("sodium_init() failed.");
                return false;
        }
        memset(out, 0, sizeof(*out));

        // Generate ephemeral X25519 keypair
        u8 my_pk[CRYPTO_PUBKEYB];
        u8 my_sk[CRYPTO_SECKEYB];
        crypto_kx_keypair(my_pk, my_sk);
        log_debug("Generated ephemeral X25519 keypair.");

        // Key exchange
        if (!net_send_all(fd, my_pk, sizeof(my_pk))) {
                log_error("Failed to send public key.");
                goto fail;
        }
        u8 pr_pk[CRYPTO_PUBKEYB];
        if (!net_recv_all(fd, pr_pk, sizeof(pr_pk))) {
                log_error("Failed to recv peer's public key.");
                goto fail;
        }
        log_debug("Exchanged public keys.");

        // Derive shared symmtric key
        u8 key[CRYPTO_KEY_BYTES];
        if (!derive_shared_key(my_pk, my_sk, pr_pk, key)) {
                goto fail;
        }
        sodium_memzero(my_sk, sizeof(my_sk));
        log_debug("Derived shared symmetric key.");

        // Init tx stream, send header
        u8 tx_hdr[CRYPTO_HDR_BYTES];
        if (crypto_secretstream_xchacha20poly1305_init_push(
                                &out->tx, tx_hdr, key) != 0) {
                log_error("init_push() failed.");
                sodium_memzero(key, sizeof(key));
                goto fail;
        }
        if (!net_send_all(fd, tx_hdr, sizeof(tx_hdr))) {
                log_error("Failed to send tx header.");
                sodium_memzero(key, sizeof(key));
                goto fail;
        }

        // Receive peer header, init rx stream
        u8 rx_hdr[CRYPTO_HDR_BYTES];
        if (!net_recv_all(fd, rx_hdr, sizeof(rx_hdr))) {
                log_error("Failed to receive rx header.");
                sodium_memzero(key, sizeof(key));
                goto fail;
        }
        if (crypto_secretstream_xchacha20poly1305_init_pull(
                                &out->rx, rx_hdr, key) != 0) {
                log_error("init_pull failed (bad header).");
                sodium_memzero(key, sizeof(key));
                goto fail;
        }
        sodium_memzero(key, sizeof(key));
        log_debug("Secretstream initialized in both directions.");

        return true;

fail:
        sodium_memzero(my_sk, sizeof(my_sk));
        sodium_memzero(out, sizeof(*out));
        return false;
}

bool crypto_send_typed(i32 fd, u8 type,
                       const u8 *data, u32 len,
                       CryptoSession *s)
{
        if ((u64)len + 1 + CRYPTO_TAG_BYTES > CRYPTO_MAX_FRAME) {
                log_error("send_typed(): payload too large (%u).", len);
                return false;
        }

        u32 pt_len = 1 + len;
        u32 ct_len = pt_len + CRYPTO_TAG_BYTES;

        /*
         * Stack buffer for the common case (chat messages, control
         * frames are all tiny). Heap fallback for anything bigger,
         * though in this branch nothing should hit that path.
         */
        u8 stack_pt[2 * KB];
        u8 stack_ct[2 * KB + CRYPTO_TAG_BYTES];
        u8 *pt = (pt_len <= sizeof(stack_pt)) ? stack_pt : malloc(pt_len);
        u8 *ct = (ct_len <= sizeof(stack_ct)) ? stack_ct : malloc(ct_len);
        if (!pt || !ct) {
                log_error("send_typed(): malloc failed.");
                if (pt && pt != stack_pt) free(pt);
                if (ct && ct != stack_ct) free(ct);
                return false;
        }

        pt[0] = type;
        if (len > 0 && data != NULL) memcpy(pt + 1, data, len);

        unsigned long long actual_ct_len = 0;
        int rc = crypto_secretstream_xchacha20poly1305_push(
                        &s->tx, ct, &actual_ct_len,
                        pt, pt_len,
                        NULL, 0,
                        crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);

        sodium_memzero(pt, pt_len);
        if (pt != stack_pt) free(pt);

        if (rc != 0) {
                log_error("secretstream_push(): failed.");
                if (ct != stack_ct) free(ct);
                return false;
        }

        u32 net_len = htonl((u32)actual_ct_len);
        bool ok = net_send_all(fd, &net_len, sizeof(net_len))
               && net_send_all(fd, ct, (size_t)actual_ct_len);

        if (ct != stack_ct) free(ct);
        return ok;
}

bool crypto_recv_typed(i32 fd,
                       u8 *out_type,
                       u8 **out_data,
                       u32 *out_len,
                       CryptoSession *s)
{
        // Read length first
        u32 net_len;
        if (!net_recv_all(fd, &net_len, sizeof(net_len))) return false;
        u32 ct_len = ntohl(net_len);

        // Validate
        if (ct_len < CRYPTO_TAG_BYTES + 1 || ct_len > CRYPTO_MAX_FRAME) {
                log_error("recv_typed(): bad frame length %u.", ct_len);
                return false;
        }

        // Read ciphertext
        u8 *ct = malloc(ct_len);
        if (!ct) {
                log_error("recv_typed(): malloc(ct) failed.");
                return false;
        }
        if (!net_recv_all(fd, ct, ct_len)) {
                log_error("recv_typed(): recv_all(ciphertext) failed.");
                free(ct);
                return false;
        }

        // Decrypt
        u32 pt_len = ct_len - CRYPTO_TAG_BYTES;
        u8 *pt = malloc(pt_len + 1);
        if (!pt) {
                log_error("recv_typed(): malloc(pt) failed.");
                free(ct);
                return false;
        }

        unsigned long long actual_pt_len = 0;
        u8 tag = 0;
        int rc = crypto_secretstream_xchacha20poly1305_pull(
                        &s->rx, pt, &actual_pt_len, &tag,
                        ct, ct_len,
                        NULL, 0);
        free(ct);

        if (rc != 0) {
                log_error("secretstream_pull() failed: forged or corrupted.");
                goto fail_rt;
        }
        s->last_rx_tag = tag;

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
                /* The control stream is supposed to live until the TCP
                 * closes. A peer sending TAG_FINAL is either buggy or
                 * malicious -> treat as a protocol error */
                log_error("Unexpected TAG_FINAL on control stream.");
                goto fail_rt;
        }

        if (actual_pt_len < 1) {
                log_error("recv_typed(): empty plaintext (no type byte).");
                goto fail_rt;
        }

        *out_type = pt[0];

        /* Shift payload by one byte (type byte) */
        u32 payload_len = (u32)actual_pt_len - 1;
        memmove(pt, pt + 1, payload_len);
        pt[payload_len] = '\0';

        *out_data = pt;
        *out_len = payload_len;
        return true;

fail_rt:
        sodium_memzero(pt, pt_len);
        free(pt);
        return false;
}

void crypto_session_close(CryptoSession *s)
{
        if (!s) return;
        sodium_memzero(s, sizeof(*s));
}
