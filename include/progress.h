#ifndef PROGRESS_H
#define PROGRESS_H

#include "typedefs.h"
#include <time.h>
#include <pthread.h>
#include <stdbool.h>

/*
 * progress.h -- file-transfer progress display.
 */
#define PROGRESS_INTERVAL_MS 100
#define PROGRESS_BAR_WIDTH   20

typedef struct {
        const char      *label;
        u64             total;
        u64             current;
        struct timespec started;
        struct timespec last_drawn;
        pthread_mutex_t *io_lock;
} ProgressBar;

/*
 * Begin a transfer. Records start time, draws an initial 0% bar.
 * Caller must have io_lock available; lock it during draws.
 */
void progress_init(ProgressBar *p, const char *label,
                   u64 total_bytes, pthread_mutex_t *io_lock);

/*
 * Update with cumulative bytes. Called per chunk, but only redraws
 * if PROGRESS_INTERVAL_MS has elapsed since the last redraw, OR if
 * current >= total (last update always to show 100%).
 */
void progress_tick(ProgressBar *p, u64 current_bytes);

/*
 * Final cleanup: draw a 100% line and emit a newline so subsequent
 * output starts fresh.
 */
void progress_done(ProgressBar *p);

#endif
