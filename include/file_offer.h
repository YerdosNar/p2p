#ifndef FILE_OFFER_H
#define FILE_OFFER_H

#include "typedefs.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define FILE_NAME_MAX 255

/*
 * file_offer.h -- offer/accept exchange.
 *
 * Wire format for MSG_FILE_OFFER:
 *   [ size:     8 bytes, network order  ]
 *   [ name_len: 1 byte                  ]
 *   [ name:     name_len bytes          ]
 *
 * MSG_FILE_ACCEPT, MSG_FILE_REJECT carry no payload.
 *
 * This branch implements only the metadata round-trip. Actual file
 * bytes are deferred to feat/file-stream.
 */

typedef struct {
        char    name[FILE_NAME_MAX + 1];
        u64     size;
        bool    valid;
} FileOffer;

/*
 * Build an MSG_FILE_OFFER payload from a name + size.
 *
 * out_buf must have at least 8 + 1 + FILE_NAME_MAX bytes.
 * On success: writes payload, sets *out_len, returns true.
 * On failure (name too long, etc.): returns false.
 */
bool file_offer_build(const char *name, u64 size,
                      u8 *out_buf, u32 *out_len);

/*
 * Parse an MSG_FILE_OFFER payload into a FileOffer.
 * Returns true on success. Sets out->valid = true on success.
 */
bool file_offer_parse(const u8 *payload, u32 len, FileOffer *out);

/*
 * Sanitize a filename received from the peer.
 *
 * Strips path separators, rejects leading dots, rejects empty results.
 * Writes safe name to out (max FILE_NAME_MAX + 1 bytes including NUL).
 * Returns true on success, false if the name is unsafe (caller should
 * reject the offer or auto-pick a fallback name).
 */
bool file_offer_sanitize_name(const char *in, char *out, size_t out_size);

/*
 * Format a size in human-readable form ("12.3 MB", "1.4 GB").
 * out_buf needs ~16 chars. Always NUL-terminated.
 */
void file_offer_format_size(u64 bytes, char *out_buf, size_t out_size);

#endif /* FILE_OFFER_H */
