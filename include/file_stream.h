#ifndef FILE_STREAM_H
#define FILE_STREAM_H

#include "crypto.h"
#include "file_offer.h"
#include "typedefs.h"

#include <stdbool.h>

/*
 * file_stream.h - streaming a single file over an established P2P session.
 *
 * Both functions are blocking. Run then from the recv thread (which
 * already own the socket). During a transfer the chat send thread
 * shoudl be in XFER_ACTIVE mode, suppressing input.
 */

/*
 * Sender side. Open `path`, create transfer stream, send TRANSFER_HEADER
 * over the control stream, then push file contents in chunks (last with
 * TAG_FINAL). Return true on success.
 *
 * Does not wait for MSG_TRANFER_DONE - caller's recv loop picks that up.
 */
bool file_stream_send(i32 fd, CryptoSession *control,
                      const char *path, u64 expected_size);

/*
 * Receiver side. Reads MSG_TRANSFER_HEADER from the control stream
 * (already known to be the next message), opens output file (auto-renamed
 * on collision), pulls chunks, writes them, until TAG_FINAL.
 *
 * On success: file is renamed form .partial to its final name, and
 *             MSG_TRANFER_DONE is sent. Returns true
 *
 * On failure: partial file is deleted, returns false. Connection state
 *             is left to the caller to clean up.
 */
bool file_stream_recv(i32 fd, CryptoSession *control,
                      const FileOffer *offer,
                      const u8 *hdr_payload, u32 header_len);

#endif
