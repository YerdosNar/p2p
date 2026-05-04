#include "../include/chat.h"
#include "../include/typedefs.h"
#include "../include/logger.h"
#include "../include/msgtype.h"

#include <pthread.h>
#include <signal.h>
#include <termios.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define INPUT_BUF_MAX   KB
#define PROMPT          "> "

static size_t           g_input_len     = 0;
static pthread_mutex_t  g_input_lock    = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t  g_io_lock       = PTHREAD_MUTEX_INITIALIZER;
static bool             g_tio_saved     = false;
static i32              g_fd            = -1;
static CryptoSession   *g_session       = NULL;
static char             g_input           [INPUT_BUF_MAX];
static struct termios   g_old_tio;

static void restore_termios(void)
{
        if (g_tio_saved) {
                tcsetattr(STDIN_FILENO, TCSANOW, &g_old_tio);
                g_tio_saved = false;
        }
}

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
                log_error("stdin is not terminal; chat needs interactive tty");
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
         * ICANON off - read each char as it arrives, no line buffering
         * ECHO   off - we echo manually so we control timing
         * ISIG   on  - keep Ctrl-C generating SIGINT (handler restores tio)
         * IEXTEN off - disable Ctrl-V literal-next, not useful here
         * Other flags left at default; we're not aiming for full vt100.
         */
        raw.c_lflag &= ~(ICANON | ECHO | IEXTEN);
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) {
                log_error("tcsetattr: %s", strerror(errno));
                return false;
        }

        struct sigaction sa = {0};
        sa.sa_handler = on_signal;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        return true;
}

static void io_write_raw(const char *s, size_t n)
{
        ssize_t _ = write(STDOUT_FILENO, s, n);
        (void)_;
}
static void io_write_str(const char *s) {io_write_raw(s, strlen(s));}

/*
 * Erase the current visible line (prompt + partial input) and replace
 * it with `text`, then redraw the prompt + partial input so the user's
 * cursor ends where they left off.
 *
 * Caller must hold both lock: input first, then io. THis snapshots
 * input under the input lock and writes under the io lock.
 */
static void redraw_with_message(const char *prefix, const char *msg, size_t msg_len)
{
        /* \r return cursor to column 0, \x1b[K erase to end of line .*/
        io_write_str("\r\x1b[K");
        io_write_str(prefix);
        io_write_raw(msg, msg_len);
        io_write_str("\n");
        io_write_str(PROMPT);
        io_write_raw(g_input, g_input_len);
}

static void *recv_thread(void *arg)
{
        (void)arg;
        for (;;) {
                u8 type;
                u8 *data = NULL;
                u32 len = 0;
                if (!crypto_recv_typed(g_fd, &type, &data, &len, g_session)) {
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
                pthread_mutex_lock(&g_input_lock);
                pthread_mutex_lock(&g_io_lock);
                redraw_with_message("<peer> ", (const char *)data, len);
                pthread_mutex_unlock(&g_io_lock);
                pthread_mutex_unlock(&g_input_lock);
                restore_termios();
                free(data);
        }
        return NULL;
}

/* Read one char. Return -1 on EOF/error. EINTR is retried.*/
static int read_one_char(void)
{
        for (;;) {
                u8 c;
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
        pthread_mutex_unlock(&g_input_lock);

        /* Newline + new prompt regardless of whether we send. */
        pthread_mutex_lock(&g_io_lock);
        io_write_str("\n");
        pthread_mutex_unlock(&g_io_lock);

        if (line_len == 0) {
                // empty line
                pthread_mutex_lock(&g_io_lock);
                io_write_str(PROMPT);
                pthread_mutex_unlock(&g_io_lock);
                return true;
        }

        if (!strncmp(line, "/quit", 5)) {
                crypto_send_typed(g_fd, MSG_BYE, NULL, 0, g_session);
                return false;
        }

        if (!crypto_send_typed(g_fd, MSG_CHAT, (const u8 *)line,
                                (u32)line_len, g_session)) {
                pthread_mutex_lock(&g_io_lock);
                io_write_str("(send failed)\n");
                io_write_str(PROMPT);
                pthread_mutex_unlock(&g_io_lock);
                return true;
        }

        pthread_mutex_lock(&g_io_lock);
        io_write_str(PROMPT);
        pthread_mutex_unlock(&g_io_lock);
        return true;
}

static void handle_char(int c)
{
        if (c == '\r' || c == '\n') {
                if (!dispatch_line()) {
                        /* /quit - close and exit clealy*/
                        pthread_mutex_lock(&g_io_lock);
                        io_write_str("Disconnecting.\n");
                        pthread_mutex_unlock(&g_io_lock);
                        restore_termios();
                        _exit(0);
                }
                return;
        }

        if (c == 127 || c == 8) { /* BACKSPACE or DEL */
                pthread_mutex_lock(&g_input_lock);
                if (g_input_len > 0) {
                        g_input_len--;
                        pthread_mutex_lock(&g_io_lock);
                        /* move cursor back, overwrite with space, move back*/
                        io_write_str("\b \b");
                        pthread_mutex_unlock(&g_io_lock);
                }
                pthread_mutex_unlock(&g_input_lock);
                return;
        }

        if (c == 4) { /* Ctrl+D = EOF when buffer empty */
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
                /* Non-printables */
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
        pthread_mutex_unlock(&g_input_lock);
}

void chat_run(i32 fd, CryptoSession *s, const char *peer_fp)
{
        g_fd = fd;
        g_session = s;

        if (!enter_raw_mode()) {
                log_error("Cannot enter raw mode; char unavailable.");
                return;
        }

        // Banner
        pthread_mutex_lock(&g_io_lock);
        printf("Chatting with peer (fingerprint %s). Type /quit or Ctrl-D to exit\n",
                        peer_fp);
        fflush(stdout);
        io_write_str(PROMPT);
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
                        // EOF or error
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
