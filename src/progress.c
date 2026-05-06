#include "../include/progress.h"
#include "../include/file_offer.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

/*
 * Block chars for the bar, UTF-8 encoded.
 *   U+2588 FULL BLOCK  = 0xE2 0x96 0x88
 *   U+2591 LIGHT SHADE = 0xE2 0x96 0x91
 */

#define FULL_BLOCK  "\xE2\x96\x88"
#define LIGHT_SHADE "\xE2\x96\x91"
#define PROGRESS_BAR_MIN        10
#define PROGRESS_BAR_MAX        60
#define PROGRESS_LABEL_RESERVE  75

static u16 get_term_width(void)
{
        struct winsize ws;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col)
                return (u16)ws.ws_col;
        if (ioctl(STDIN_FILENO,  TIOCGWINSZ, &ws) == 0 && ws.ws_col)
                return (u16)ws.ws_col;
        if (ioctl(STDERR_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col)
                return (u16)ws.ws_col;
        return (u16)PROGRESS_BAR_WIDTH;
}

static u16 compute_bar_width(u16 tty_width)
{
        u16 available = tty_width - PROGRESS_LABEL_RESERVE;
        if (available < PROGRESS_BAR_MIN) return PROGRESS_BAR_MIN;
        if (available > PROGRESS_BAR_MAX) return PROGRESS_BAR_MAX;
        return available;
}

static bool stdout_is_tty(void)
{
        static int cached = -1;
        if (cached == -1) cached = isatty(STDOUT_FILENO) ? 1 : 0;
        return cached == 1;
}

static double seconds_between(struct timespec a, struct timespec b)
{
        return (double)(b.tv_sec  - a.tv_sec)
             + (double)(b.tv_nsec - a.tv_nsec) / 1e9;
}

static long ms_between(struct timespec a, struct timespec b)
{
        return (b.tv_sec  - a.tv_sec)  * 1000L
             + (b.tv_nsec - a.tv_nsec) / 1000000L;
}

static void format_rate(double bytes_per_sec, char *out, size_t out_size)
{
        char tmp[16];
        file_offer_format_size((u64)bytes_per_sec, tmp, sizeof(tmp));
        snprintf(out, out_size, "%s/s", tmp);
}

static void format_eta(double seconds, char *out, size_t out_size)
{
        if (seconds < 0 || seconds > 99 * 3600) {
                snprintf(out, out_size, "--");
                return;
        }
        if (seconds < 60.0) {
                snprintf(out, out_size, "%.0fs", seconds);
        } else if (seconds < 3600.0) {
                int m = (int)(seconds / 60.0);
                int s = (int)(seconds - m * 60.0);
                snprintf(out, out_size, "%dm %ds", m, s);
        } else {
                int h = (int)(seconds / 3600.0);
                int m = (int)((seconds - h * 3600.0) / 60);
                snprintf(out, out_size, "%dh %dm", h, m);
        }
}

static void draw(ProgressBar *p, struct timespec now)
{
        double elapsed  = seconds_between(p->started, now);
        double rate     = elapsed > 0.01 ? (double)p->current / elapsed : 0.0;
        double eta      = (rate > 0.01 && p->current < p->total)
                        ? (double)(p->total - p->current) / rate
                        : 0.0;

        int filled = 0;
        if (p->total > 0) {
                filled = (int)((p->current * (u64)p->tty_width)
                                / p->total);
        }
        if (filled > p->tty_width) filled = p->tty_width;
        int empty = p->tty_width - filled;

        int pct = 0;
        if (p->total > 0) {
                pct = (int)((p->current * 100ULL) / p->total);
        }
        if (pct > 100) pct = 100;

        char cur_str[16], tot_str[16], rate_str[24], eta_str[16];
        file_offer_format_size(p->current, cur_str, sizeof(cur_str));
        file_offer_format_size(p->total,   tot_str, sizeof(tot_str));
        format_rate(rate, rate_str, sizeof(rate_str));
        format_eta(eta, eta_str, sizeof(eta_str));

        // One buffer for the whole line
        char line[512];
        size_t pos = 0;

        /* Erase line, position at 0 */
        const char prefix[] = "\r\x1b[K";
        memcpy(line + pos, prefix, sizeof(prefix) - 1);
        pos += sizeof(prefix) - 1;

        /* Label */
        int n = snprintf(line + pos, sizeof(line) - pos, "%s [", p->label);
        if (n > 0) pos += (size_t)n;

        /* Filled blocks */
        for (int i = 0; i < filled && pos + 3 < sizeof(line); i++) {
                memcpy(line + pos, FULL_BLOCK, 3);
                pos += 3;
        }
        for (int i = 0; i < empty && pos + 3 < sizeof(line); i++) {
                memcpy(line + pos, LIGHT_SHADE, 3);
                pos += 3;
        }

        /* Rest of the stats */
        n = snprintf(line + pos, sizeof(line) - pos,
                     "] %3d \xE2\x80\x94 %s / %s \xE2\x80\x94 %s "
                     "\xE2\x80\x94 ETA %s",
                     pct, cur_str, tot_str, rate_str, eta_str);
        if (n > 0) pos += (size_t)n;

        ssize_t _ = write(STDOUT_FILENO, line, pos);
        (void)_;
}

void progress_init(ProgressBar *p, const char *label,
                   u64 total_bytes, pthread_mutex_t *io_lock)
{
        memset(p, 0, sizeof(*p));
        p->label        = label;
        p->tty_width    = compute_bar_width(get_term_width());
        p->total        = total_bytes;
        p->current      = 0;
        p->io_lock      = io_lock;
        clock_gettime(CLOCK_MONOTONIC, &p->started);
        p->last_drawn   = p->started;

        pthread_mutex_lock(p->io_lock);
        draw(p, p->started);
        pthread_mutex_unlock(p->io_lock);
}

void progress_tick(ProgressBar *p, u64 current_bytes)
{
        p->current = current_bytes;
        if (!stdout_is_tty()) return;

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        bool is_final = (current_bytes >= p->total);
        bool throttle_ok = ms_between(p->last_drawn, now)
                                >= PROGRESS_INTERVAL_MS;

        if (!is_final && !throttle_ok) return;

        p->last_drawn = now;
        pthread_mutex_lock(p->io_lock);
        draw(p, now);
        pthread_mutex_unlock(p->io_lock);
}

void progress_done(ProgressBar *p)
{
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        p->current = p->total;

        pthread_mutex_lock(p->io_lock);
        if (stdout_is_tty()) {
                draw(p, now);
                ssize_t _ = write(STDOUT_FILENO, "\n", 1);
                (void)_;
        } else {
                /* Non-TTY: emit a single summary line. */
                double elapsed = seconds_between(p->started, now);
                char tot[16], rate[24];
                file_offer_format_size(p->total, tot, sizeof(tot));
                format_rate(elapsed > 0.01 ? p->total / elapsed : 0,
                            rate, sizeof(rate));
                char line[128];
                int n = snprintf(line, sizeof(line),
                                 "%s complete: %s in %.1fs (%s)\n",
                                 p->label, tot, elapsed, rate);
                if (n > 0) {
                        ssize_t _ = write(STDOUT_FILENO, line, (size_t)n);
                        (void)_;
                }
        }
        pthread_mutex_unlock(p->io_lock);
}
