#ifndef IDENTITY_H
#define IDENTITY_H

#include "typedefs.h"

#include <sodium.h>
#include <stdbool.h>

/*
 * identity.h - long-lived peer identity (X25519 keypair).
 *
 * The keypair persists across invocations in
 * $XDG_CONFIG_HOME/openp2p/identity.key (or ~/.config/openp2p/identity.key)
 * File format: 64 raw bytes - 32 secret + 32 public.
 * Permissions: file 0600, directory 0700. Loading refuses files with
 * looser perms (matches SSH conventions).
 *
 * The secret half MUST never leave this process (no logging, no
 * sending over the wire, no error messages including its bytes).
 * The public half is the identity advertised to peers via
 * PROTO_PUBKEY
 */

#define IDENTITY_PUBKEY_BYTES crypto_kx_PUBLICKEYBYTES
#define IDENTITY_SECKEY_BYTES crypto_kx_SECRETKEYBYTES

/*
 * Human-readable fingerprint length: 4 groups of 4 hex chars,
 * separated by spaces. e.g. "1a2b 3c4d 5e6f 7a8b 9c0d".
 *
 * 16 hex chars = 8 bytes = 64 bits of pubkey shown. Enough for
 * eyeball comparison; users won't read all 32 bytes verbally.
 * Format chosen to match Signal's safety-numbers style.
 */
#define IDENTITY_FINGERPRINT_BYTES 19 /* "XXXX XXXX XXXX XXXX" + NUL */

typedef struct {
        u8 pubkey[IDENTITY_PUBKEY_BYTES];
        u8 seckey[IDENTITY_SECKEY_BYTES];
} Identity;

/*
 * Load identity from path, or generate-and-save if path doesn't exist.
 *
 * If path is NULL, uses the default location ($XDG_CONFIG_HOME/openp2p/
 * or ~/.config/openp2p/ with the filename "identity.key")
 *
 * On success: returns true.
 * On failure: returns false, *out is zeroed, error is logged.
 *
 * Failure modes:
 *   - File exists but unreadable / wrong size / bad permissions
 *   - Directory creation failed (permissions, disk full, etc.)
 *   - Cannot determine home directory (no $HOME, no $XDG_CONFIG_HOME)
 */
bool identity_load_or_create(Identity *out, const char *path);

/*
 * Format the public key as a Human-readable finagerprint.
 *
 * out_buf must have room for IDENTITY_FINGERPRINT_BYTES (19) chars
 * including the trailing NUL. Always writes a NUL-terminated string.
 *
 * The fingerprint is the first 8 bytes of the pubkey, shown as four
 * groups of 4 lowercase hex chars separated by spaces.
 */
void identity_fingerprint(const u8 pubkey[IDENTITY_PUBKEY_BYTES],
                          char out_buf[IDENTITY_FINGERPRINT_BYTES]);

/*
 * Zero the secret key. Safe to call on a partially-initialized
 * Identity (e.g. after a filed load).
 */
void identity_close(Identity *id);

#endif
