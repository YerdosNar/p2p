#include "../include/file_stream.h"
#include "../include/crypto.h"
#include "../include/msgtype.h"
#include "../include/logger.h"
#include "../include/typedefs.h"
#include "../include/progress.h"

#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sodium.h>

/*
 * Find a non-existing path of the form "name", "name_1", "name_2", ...
 * up to (999). Writes result to out (size out_size). Returns false if
 * we can't find a free slot in 1000 tries... Crazy...
 *
 * Splits the name at the LAST fot for the suffic to feel natural:
 *      "report.pdf"    -> "report_1.pdf"
 *      "archive.tar.gx"-> "archive.tar_1.gz"
 *      "notes"         -> "notes_1"
 */
static bool find_free_path(const char *name, char *out, size_t out_size)
{
        if (access(name, F_OK) != 0) {
                if (snprintf(out, out_size, "%s", name) >= (int)out_size)
                        return false;
                return true;
        }

        const char *dot = strrchr(name, '.');
        size_t stem_len = dot ? (size_t)(dot - name) : strlen(name);
        const char *suffix = dot ? dot : "";

        for (int n = 1; n <= 999; n++) {
                int written = snprintf(out, out_size, "%.*s_%d%s",
                                       (int)stem_len, name, n, suffix);
                if (written < 0 || (size_t)written >= out_size) return false;
                if (access(out, F_OK) != 0) return true;
        }
        return false;
}

/*
 * write() loop. Returns true if all bytes were written. EINTR retried.
 */
static bool write_all(i32 fd, const void *buf, size_t len)
{
        const u8 *p = buf;
        size_t total = 0;
        while (total < len) {
                ssize_t w = write(fd, p + total, len - total);
                if (w > 0) { total += (size_t)w; continue; }
                if (errno == EINTR) continue;
                return false;
        }
        return true;
}

/*
 * read() one chunk. Returns the number of bytes actually read (0..max).
 * Return -1 on error. EINTR retried.
 */
static ssize_t read_chunk(i32 fd, u8 *buf, size_t max)
{
        size_t total = 0;
        while (total < max) {
                ssize_t r = read(fd, buf + total, max - total);
                if (r > 0) { total += (size_t)r; continue; }
                if (r == 0) break;
                if (errno == EINTR) continue;
                return -1;
        }
        return (ssize_t)total;
}

bool file_stream_send(i32 fd, CryptoSession *control,
                 const char *path, u64 expected_size,
                 pthread_mutex_t *io_lock)
{
        int src = open(path, O_RDONLY);
        if (src < 0) {
                log_error("open(%s): %s", path, strerror(errno));
                return false;
        }

        /* Init transfer stream + send key+hdr over control stream */
        XferStreamTx tx;
        u8 key[XFER_KEY_BYTES];
        u8 hdr[XFER_HDR_BYTES];
        if (!crypto_xfer_init_sender(&tx, key, hdr)) {
                close(src);
                return false;
        }

        u8 hdr_payload[XFER_KEY_BYTES + XFER_HDR_BYTES];
        memcpy(hdr_payload, key, XFER_KEY_BYTES);
        memcpy(hdr_payload + XFER_KEY_BYTES, hdr, XFER_HDR_BYTES);

        bool ok = crypto_send_typed(fd, MSG_TRANSFER_HDR,
                                    hdr_payload, sizeof(hdr_payload),
                                    control);
        sodium_memzero(key, sizeof(key));
        sodium_memzero(hdr_payload, sizeof(hdr_payload));
        if (!ok) {
                log_error("Failed to send MSG_TRANSFER_HDR");
                close(src);
                crypto_xfer_close(&tx);
                return false;
        }

        // Push chunks
        u8 buf[XFER_MAX_CHUNK];
        u64 total_sent = 0;
        bool success = true;

        ProgressBar pb;
        progress_init(&pb, "Sending", expected_size, io_lock);
        if (expected_size == 0) {
                if (!crypto_xfer_send_chunk(fd, &tx, buf, 0,
                            crypto_secretstream_xchacha20poly1305_TAG_FINAL)) {
                        success = false;
                }
        } else {
                for (;;) {
                        size_t want = sizeof(buf);
                        u64 remaining = expected_size - total_sent;
                        if ((u64)want > remaining) want = (size_t)remaining;

                        ssize_t n = read_chunk(src, buf, want);
                        if (n < 0) {
                                log_error("read failed mid-transfer: %s",
                                          strerror(errno));
                                success = false;
                                break;
                        }
                        if (n == 0 && total_sent < expected_size) {
                                log_error("File truncated mid-transfer "
                                          "(got %llu, expected %llu)",
                                          (unsigned long long)total_sent,
                                          (unsigned long long)expected_size);
                                success = false;
                                break;
                        }

                        bool is_last = (total_sent + (u64)n
                                        >= expected_size);
                        u8 tag = is_last
                                ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                                : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

                        if (!crypto_xfer_send_chunk(fd, &tx, buf,
                                                (u32)n, tag)) {
                                log_error("Failed to send chunk at offset %llu",
                                          (unsigned long long)total_sent);
                                success = false;
                                break;
                        }
                        total_sent += (u64)n;
                        progress_tick(&pb, total_sent);
                        if (is_last) break;
                }
        }
        if (success) progress_done(&pb);

        sodium_memzero(buf, sizeof(buf));
        close(src);
        crypto_xfer_close(&tx);
        return success;
}

bool file_stream_recv(i32 fd, CryptoSession *control,
                      const FileOffer *offer,
                      const u8 *hdr_payload, u32 hdr_len,
                      pthread_mutex_t *io_lock)
{
        (void)control;
        if (hdr_len != XFER_KEY_BYTES + XFER_HDR_BYTES) {
                log_error("Bad MSG_TRANSFER_HDR length %u", hdr_len);
                return false;
        }

        XferStreamRx rx;
        bool inited = crypto_xfer_init_receiver(&rx,
                                hdr_payload,
                                hdr_payload + XFER_KEY_BYTES);
        if (!inited) return false;

        /* Pick output path */
        char final_path[FILE_NAME_MAX + 32];
        if (!find_free_path(offer->name, final_path, sizeof(final_path))) {
                log_error("Cannot find non-colliding path for %s", offer->name);
                crypto_xfer_close(&rx);
                return false;
        }

        char partial[FILE_NAME_MAX + 64];
        if (snprintf(partial, sizeof(partial), "%s.partial", final_path)
                        >= (int)sizeof(partial)) {
                log_error("Partial filename too long");
                crypto_xfer_close(&rx);
                return false;
        }

        int dst = open(partial, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (dst < 0) {
                log_error("open(%s): %s", partial, strerror(errno));
                crypto_xfer_close(&rx);
                return false;
        }

        /* Pull loop until TAG_FINAL */
        u64 total_recv = 0;
        bool success = true;

        ProgressBar pb;
        progress_init(&pb, "Receiving", offer->size, io_lock);
        for (;;) {
                u8 *chunk = NULL;
                u32 clen = 0;
                if (!crypto_xfer_recv_chunk(fd, &rx, &chunk, &clen)) {
                        log_error("Receive failed at offset %llu",
                                        (unsigned long long)total_recv);
                        success = false;
                        break;
                }

                if (clen > 0 && !write_all(dst, chunk, clen)) {
                        log_error("write failed at offset %llu: %s",
                                  (unsigned long long)total_recv,
                                  strerror(errno));
                        sodium_memzero(chunk, clen);
                        free(chunk);
                        success = false;
                        break;
                }
                total_recv += (u64)clen;
                progress_tick(&pb, total_recv);
                sodium_memzero(chunk, clen);
                free(chunk);

                if (rx.last_tag
                    == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
                        break;
        }

        crypto_xfer_close(&rx);
        if (close(dst) != 0) {
                log_error("close(%s): %s", partial, strerror(errno));
                success = false;
        }

        if (!success) {
                unlink(partial);
                return false;
        } else {
                progress_done(&pb);
        }

        if (total_recv != offer->size) {
                log_warn("Received %llu bytes, offer claimed %llu",
                         (unsigned long long)total_recv,
                         (unsigned long long)offer->size);
                /* Not strictly fatal - the bytes are authentic;
                 * the offer was just wrong about size. Keep the file.*/
        }

        if (rename(partial, final_path) != 0) {
                log_error("rename(%s -> %s): %s",
                          partial, final_path, strerror(errno));
                unlink(partial);
                return false;
        }

        log_info("Saved %s (%llu bytes)", final_path,
                 (unsigned long long)total_recv);

        /* Acknowledge */
        if (!crypto_send_typed(fd, MSG_TRANSFER_DONE, NULL, 0, control)) {
                log_warn("Failed to send MSG_TRANSFER_DONE (file is on disk anyway)");
        }
        return true;
}
