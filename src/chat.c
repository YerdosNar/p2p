#include "../include/chat.h"
#include "../include/crypto.h"
#include "../include/msgtype.h"
#include "../include/logger.h"
#include "../include/typedefs.h"
#include "../include/file_offer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <termios.h>
#include <errno.h>
#include <sys/stat.h>
#include <libgen.h>

#define INPUT_BUF_MAX 1024

/*
 * Transfer mode state. Only one offer is in flight at a time.
 * "Outgoing pending" means we sent an offer and are waiting for ACCEPT/REJECT
 * "Incoming pending" measn we received an offer and are showing y/n prompt.
 * If either is set, chat input is suspended.
 */
typedef enum {
        XFER_IDLE,
        XFER_OUTGOING_PENDING,
        XFER_INCOMING_PENDING,
} XferMode;

static XferMode        g_xfer_mode = XFER_IDLE;
static FileOffer       g_incoming_offer;
static char            g_outgoing_name[FILE_NAME_MAX + 1];
static u64             g_outgoing_size;

/* Input buffer: what the user has typed so far on the current line. */
static char            g_input[INPUT_BUF_MAX];
static size_t          g_input_len = 0;
static pthread_mutex_t g_input_lock = PTHREAD_MUTEX_INITIALIZER;

/* Stdout serialization. */
static pthread_mutex_t g_io_lock = PTHREAD_MUTEX_INITIALIZER;

/* Saved termios for restore. */
static struct termios  g_old_tio;
static bool            g_tio_saved = false;

/* Connection state. Shared by signal handler and threads. */
static int             g_fd      = -1;
static CryptoSession  *g_session = NULL;

/* Names for UI */
static char           g_peer_name[34], g_my_name[34];

/* FUntion prototype */
static bool handle_incoming_response(const char *line, size_t len);
static bool handle_send_command(const char *path);

/* ── termios + signal handling ───────────────────────────────────── */

static void restore_termios(void)
{
        if (g_tio_saved) {
                tcsetattr(STDIN_FILENO, TCSANOW, &g_old_tio);
                g_tio_saved = false;
        }
}

/*
 * Async-signal-safe exit path. tcsetattr is on the safe list per
 * POSIX. write() is safe. _exit avoids atexit handlers (not all of
 * which are safe). We don't try to send MSG_BYE -- crypto_send_typed
 * is not signal-safe.
 */
static void on_signal(int sig)
{
        (void)sig;
        restore_termios();
        const char msg[] = "\nInterrupted.\n";
        ssize_t _ = write(STDERR_FILENO, msg, sizeof(msg) - 1);
        (void)_;
        _exit(130);
}

static bool enter_raw_mode(void)
{
        if (!isatty(STDIN_FILENO)) {
                log_error("stdin is not a terminal; chat needs interactive tty");
                return false;
        }
        if (tcgetattr(STDIN_FILENO, &g_old_tio) != 0) {
                log_error("tcgetattr: %s", strerror(errno));
                return false;
        }
        g_tio_saved = true;
        atexit(restore_termios);

        struct termios raw = g_old_tio;
        /*
         * ICANON off  -- read each char as it arrives, no line buffering
         * ECHO   off  -- we echo manually so we control timing
         * ISIG   on   -- keep Ctrl-C generating SIGINT (handler restores tio)
         * IEXTEN off  -- disable Ctrl-V literal-next, not useful here
         * Other flags left at default; we're not aiming for full vt100.
         */
        raw.c_lflag &= ~(ICANON | ECHO | IEXTEN);
        raw.c_cc[VMIN]  = 1;   /* read returns after >=1 char */
        raw.c_cc[VTIME] = 0;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) {
                log_error("tcsetattr: %s", strerror(errno));
                return false;
        }

        /* Restore on common termination signals. */
        struct sigaction sa = {0};
        sa.sa_handler = on_signal;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT,  &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        return true;
}

/* ── output helpers (caller MUST hold g_io_lock) ─────────────────── */

static void io_write_raw(const char *s, size_t n)
{
        ssize_t _ = write(STDOUT_FILENO, s, n);
        (void)_;
}
static void io_write_str(const char *s) { io_write_raw(s, strlen(s)); }

/*
 * Erase the current visible line (prompt + partial input) and replace
 * it with `text`, then redraw the prompt + partial input so the user's
 * cursor ends where they left off.
 *
 * Caller must hold both locks: input first, then io. This snapshots
 * input under the input lock and writes under the io lock.
 */
static void redraw_with_message(const char *prefix, const char *msg, size_t msg_len)
{
        /* \r return cursor to column 0, \x1b[K erase to end of line. */
        io_write_str("\r\x1b[K");
        io_write_str(prefix);
        io_write_raw(msg, msg_len);
        io_write_str("\n");
        io_write_str(g_my_name);
        io_write_raw(g_input, g_input_len);
}

/* ── recv thread ─────────────────────────────────────────────────── */

static void *recv_thread(void *arg)
{
        (void)arg;
        for (;;) {
                u8  type;
                u8 *data = NULL;
                u32 len  = 0;
                if (!crypto_recv_typed(g_fd, &type, &data, &len, g_session)) {
                        /* Peer closed or framing error. */
                        pthread_mutex_lock(&g_input_lock);
                        pthread_mutex_lock(&g_io_lock);
                        io_write_str("\r\x1b[K");
                        io_write_str("Peer disconnected.\n");
                        pthread_mutex_unlock(&g_io_lock);
                        pthread_mutex_unlock(&g_input_lock);
                        restore_termios();
                        _exit(0);
                }

                if (type == MSG_BYE) {
                        free(data);
                        pthread_mutex_lock(&g_input_lock);
                        pthread_mutex_lock(&g_io_lock);
                        io_write_str("\r\x1b[K");
                        io_write_str("Peer left the chat.\n");
                        pthread_mutex_unlock(&g_io_lock);
                        pthread_mutex_unlock(&g_input_lock);
                        restore_termios();
                        _exit(0);
                }

                if (type != MSG_CHAT) {
                        log_warn("Ignoring unexpected message type 0x%02x", type);
                        free(data);
                        continue;
                }

                if (type == MSG_FILE_OFFER) {
                        FileOffer offer;
                        if (!file_offer_parse(data, len, &offer)) {
                                log_warn("Bad MSG_FILE_OFFER");
                                free(data);
                                continue;
                        }

                        pthread_mutex_lock(&g_input_lock);

                        // If already in transfer state, then REJECT
                        if (g_xfer_mode != XFER_IDLE) {
                                pthread_mutex_unlock(&g_input_lock);
                                crypto_send_typed(g_fd, MSG_FILE_REJECT, NULL, 0, g_session);
                                free(data);
                                continue;
                        }

                        // Validate filename, if unsafe, REJECT
                        char safe[FILE_NAME_MAX + 1];
                        if (!file_offer_sanitize_name(offer.name, safe, sizeof(safe))) {
                                pthread_mutex_unlock(&g_input_lock);
                                crypto_send_typed(g_fd, MSG_FILE_REJECT, NULL, 0, g_session);
                                free(data);
                                continue;
                        }
                        // Replace name with sanitized name
                        strncpy(offer.name, safe, sizeof(offer.name));
                        offer.name[sizeof(offer.name) - 1] = '\0';

                        g_incoming_offer = offer;
                        g_xfer_mode = XFER_INCOMING_PENDING;

                        char sz[32];
                        file_offer_format_size(offer.size, sz, sizeof(sz));

                        pthread_mutex_lock(&g_io_lock);
                        char prompt[FILE_NAME_MAX + 64];
                        int n = snprintf(prompt, sizeof(prompt),
                                        "Accept file '%s' (%s)? [y/n]: ",
                                        offer.name, sz);
                        /* Erase line, print promt instrad of normal one */
                        io_write_str("\r\x1b[K");
                        io_write_raw(prompt, (size_t)n);
                        pthread_mutex_unlock(&g_io_lock);
                        pthread_mutex_unlock(&g_input_lock);

                        free(data);
                        continue;
                }

                if (type == MSG_FILE_ACCEPT || type == MSG_FILE_REJECT) {
                        free(data);
                        pthread_mutex_lock(&g_input_lock);

                        if (g_xfer_mode != XFER_OUTGOING_PENDING) {
                                pthread_mutex_unlock(&g_input_lock);
                                continue;
                        }

                        const char *result = (type == MSG_FILE_ACCEPT)
                                             ? "Peer accepted. (Transfer not yet implemented.)"
                                             : "Peer declined";
                        g_xfer_mode = XFER_IDLE;

                        pthread_mutex_lock(&g_io_lock);
                        io_write_str("\r\x1b[K");
                        io_write_str(result);
                        io_write_str("\n");
                        io_write_str(g_my_name);
                        io_write_raw(g_input, g_input_len);
                        pthread_mutex_unlock(&g_io_lock);
                        pthread_mutex_unlock(&g_input_lock);
                        continue;
                }

                pthread_mutex_lock(&g_input_lock);
                pthread_mutex_lock(&g_io_lock);
                redraw_with_message(g_peer_name, (const char *)data, len);
                pthread_mutex_unlock(&g_io_lock);
                pthread_mutex_unlock(&g_input_lock);
                free(data);
        }
        return NULL;
}

/* ── send thread (= calling thread) ──────────────────────────────── */

/*
 * Read one character. Returns -1 on EOF/error. EINTR is retried.
 */
static int read_one_char(void)
{
        for (;;) {
                unsigned char c;
                ssize_t r = read(STDIN_FILENO, &c, 1);
                if (r == 1) return (int)c;
                if (r == 0) return -1;
                if (errno == EINTR) continue;
                return -1;
        }
}

/*
 * Send the current input buffer as MSG_CHAT (or MSG_BYE if it's "/quit").
 * Clears the buffer afterwards. Returns false if user issued /quit.
 */
static bool dispatch_line(void)
{
        char line[INPUT_BUF_MAX + 1];
        size_t line_len;

        pthread_mutex_lock(&g_input_lock);
        line_len = g_input_len;
        memcpy(line, g_input, line_len);
        line[line_len] = '\0';
        g_input_len = 0;
        XferMode mode = g_xfer_mode;
        pthread_mutex_unlock(&g_input_lock);

        /* If we're answering a y/n prompt, that's the only valid input */
        if (mode == XFER_INCOMING_PENDING)
                return handle_incoming_response(line, line_len);

        /* If we have an outgoing offer pending, ignore typed input
         * (it'd just confuse the user - we're blocked waiting).*/
        if (mode == XFER_OUTGOING_PENDING) {
                pthread_mutex_lock(&g_io_lock);
                io_write_str("\nWaiting for the peer's response...\n");
                io_write_str("Waiting: ");
                io_write_str(g_outgoing_name);
                io_write_str("\n");
                pthread_mutex_unlock(&g_io_lock);
                return true;
        }

        /* Newline + new prompt regardless of whether we send. */
        pthread_mutex_lock(&g_io_lock);
        io_write_str("\n");
        pthread_mutex_unlock(&g_io_lock);

        if (line_len == 0) {
                /* Empty line: just redraw the prompt. */
                pthread_mutex_lock(&g_io_lock);
                io_write_str(g_my_name);
                pthread_mutex_unlock(&g_io_lock);
                return true;
        }

        if (!strncmp(line, "/send ", 6))
                return handle_send_command(line + 6);
        if (strcmp(line, "/quit") == 0) {
                crypto_send_typed(g_fd, MSG_BYE, NULL, 0, g_session);
                return false;
        }

        if (!crypto_send_typed(g_fd, MSG_CHAT,
                               (const u8 *)line, (u32)line_len, g_session)) {
                pthread_mutex_lock(&g_io_lock);
                io_write_str("(send failed)\n");
                io_write_str(g_my_name);
                pthread_mutex_unlock(&g_io_lock);
                return true;
        }

        pthread_mutex_lock(&g_io_lock);
        io_write_str(g_my_name);
        pthread_mutex_unlock(&g_io_lock);
        return true;
}

static bool handle_incoming_response(const char *line, size_t len)
{
        bool accept = (len == 1 && (line[0] == 'y' || line[0] == 'Y'));
        bool reject = (len == 1 && (line[0] == 'n' || line[0] == 'N'));

        if (!accept && !reject) {
                /* INvalid response. Re-show the prompt */
                pthread_mutex_lock(&g_input_lock);
                FileOffer offer = g_incoming_offer;
                pthread_mutex_unlock(&g_input_lock);

                char sz[32];
                file_offer_format_size(offer.size, sz, sizeof(sz));
                pthread_mutex_lock(&g_io_lock);
                io_write_str("\nPlease answer y or n.\n");
                char prompt[FILE_NAME_MAX + 64];
                int n = snprintf(prompt, sizeof(prompt),
                                 "Accept file '%s' (%s)? [y/n]: ",
                                 offer.name, sz);
                io_write_raw(prompt, (size_t)n);
                pthread_mutex_unlock(&g_io_lock);
                return true;
        }

        crypto_send_typed(g_fd,
                          accept ? MSG_FILE_ACCEPT : MSG_FILE_REJECT,
                          NULL, 0, g_session);

        pthread_mutex_lock(&g_input_lock);
        g_xfer_mode = XFER_IDLE;
        memset(&g_incoming_offer, 0, sizeof(g_incoming_offer));
        pthread_mutex_unlock(&g_input_lock);

        pthread_mutex_lock(&g_io_lock);
        io_write_str("\n");
        io_write_str(accept ? "Accepted. (Transfer not yet implemented.)\n"
                            : "Declined.\n");
        io_write_str(g_my_name);
        pthread_mutex_unlock(&g_io_lock);
        return true;
}

/*
 * Called when user typed /send <path>
 * Stats the file, validates, sends MSG_FIEL_OFFER.
 */
static bool handle_send_command(const char *path)
{
        struct stat st;
        if (stat(path, &st) != 0) {
                pthread_mutex_lock(&g_io_lock);
                io_write_str("\nstat failed: ");
                io_write_str(path);
                io_write_str("\n");
                io_write_str(g_my_name);
                pthread_mutex_unlock(&g_io_lock);
                return true;
        }
        if (!S_ISREG(st.st_mode)) {
                pthread_mutex_lock(&g_io_lock);
                io_write_str("\nNot a regular file.\n");
                io_write_str(g_my_name);
                pthread_mutex_unlock(&g_io_lock);
                return true;
        }

        /* Strip path - send only the basename to peer. */
        const char *base = path;
        for (const char *p = path; *p; p++)
                if (*p == '/') base = p+1;

        u8 buf[8 + 1 + FILE_NAME_MAX];
        u32 buf_len;
        if (!file_offer_build(base, (u64)st.st_size, buf, &buf_len)) {
                pthread_mutex_lock(&g_io_lock);
                io_write_str("\nFilename too long or invalid.\n");
                io_write_str(g_my_name);
                pthread_mutex_unlock(&g_io_lock);
                return true;
        }

        if (!crypto_send_typed(g_fd, MSG_FILE_OFFER, buf, buf_len, g_session))
                return true;

        pthread_mutex_lock(&g_input_lock);
        g_xfer_mode = XFER_OUTGOING_PENDING;
        strncpy(g_outgoing_name, base, sizeof(g_outgoing_name) - 1);
        g_outgoing_name[sizeof(g_outgoing_name) - 1] = '\0';
        g_outgoing_size = (u64)st.st_size;
        pthread_mutex_unlock(&g_input_lock);

        char sz[32];
        file_offer_format_size((u64)st.st_size, sz, sizeof(sz));
        pthread_mutex_lock(&g_io_lock);
        io_write_str("\nWaiting for ");
        io_write_str(g_peer_name);
        io_write_str(" to accept '");
        io_write_str(base);
        io_write_str("' (");
        io_write_str(sz);
        io_write_str(")...\n");
        pthread_mutex_unlock(&g_io_lock);
        return true;
}

static void handle_char(int c)
{
        if (c == '\r' || c == '\n') {
                if (!dispatch_line()) {
                        /* /quit -- close and exit cleanly. */
                        pthread_mutex_lock(&g_io_lock);
                        io_write_str("Disconnecting.\n");
                        pthread_mutex_unlock(&g_io_lock);
                        restore_termios();
                        _exit(0);
                }
                return;
        }

        if (c == 127 || c == 8) {   /* backspace / DEL */
                pthread_mutex_lock(&g_input_lock);
                if (g_input_len > 0) {
                        g_input_len--;
                        pthread_mutex_lock(&g_io_lock);
                        /* Move cursor back, overwrite with space, move back. */
                        io_write_str("\b \b");
                        pthread_mutex_unlock(&g_io_lock);
                }
                pthread_mutex_unlock(&g_input_lock);
                return;
        }

        if (c == 4) {   /* Ctrl-D = EOF when buffer empty */
                pthread_mutex_lock(&g_input_lock);
                bool empty = (g_input_len == 0);
                pthread_mutex_unlock(&g_input_lock);
                if (empty) {
                        crypto_send_typed(g_fd, MSG_BYE, NULL, 0, g_session);
                        pthread_mutex_lock(&g_io_lock);
                        io_write_str("\nDisconnecting.\n");
                        pthread_mutex_unlock(&g_io_lock);
                        restore_termios();
                        _exit(0);
                }
                return;
        }

        if (c < 32 || c > 126) {
                /* Non-printable, ignore (covers escape sequences too). */
                return;
        }

        pthread_mutex_lock(&g_input_lock);
        if (g_input_len < INPUT_BUF_MAX - 1) {
                g_input[g_input_len++] = (char)c;
                pthread_mutex_lock(&g_io_lock);
                char ch = (char)c;
                io_write_raw(&ch, 1);
                pthread_mutex_unlock(&g_io_lock);
        }
        /* Else: buffer full, silently drop. User will hit Enter eventually. */
        pthread_mutex_unlock(&g_input_lock);
}

/* ── entry point ─────────────────────────────────────────────────── */

void chat_run(i32               fd,
              CryptoSession     *session,
              const char        *peer_fp,
              const char        *peer_name,
              const char        *my_name)
{
        g_fd         = fd;
        g_session    = session;

        snprintf(g_peer_name, sizeof(g_peer_name), "%s> ", peer_name);
        snprintf(g_my_name, sizeof(g_my_name), "%s> ", my_name);

        if (!enter_raw_mode()) {
                log_error("Cannot enter raw mode; chat unavailable.");
                return;
        }

        /* Print banner + initial prompt. */
        pthread_mutex_lock(&g_io_lock);
        printf("Chatting with peer (fingerprint %s). Type /quit or Ctrl-D to exit.\n",
               peer_fp);
        fflush(stdout);
        io_write_str(g_my_name);
        pthread_mutex_unlock(&g_io_lock);

        pthread_t rx;
        if (pthread_create(&rx, NULL, recv_thread, NULL) != 0) {
                log_error("pthread_create failed");
                restore_termios();
                return;
        }
        pthread_detach(rx);

        for (;;) {
                int c = read_one_char();
                if (c < 0) {
                        /* EOF or error on stdin. Treat as /quit. */
                        crypto_send_typed(g_fd, MSG_BYE, NULL, 0, g_session);
                        pthread_mutex_lock(&g_io_lock);
                        io_write_str("\nDisconnecting.\n");
                        pthread_mutex_unlock(&g_io_lock);
                        restore_termios();
                        _exit(0);
                }
                handle_char(c);
        }
}
