#ifndef STREAM_TABLE_H
#define STREAM_TABLE_H

#include "typedefs.h"

#include <pthread.h>
#include <stdbool.h>

/*
 * stream_table.h - thread-safe table of active proxy streams.
 *
 * One slot per concurrent stream. Joiner allocates IDs monotonically
 * (1..); host never allocates. ID 0 marks an empty slot.
 *
 * Half-close is supported via per-direction state. A stream is
 * eligible for reaping (state -> STREAM_DEAD) when both halves have
 * sent CLOSE or a fatal error occured.
 */

#define STREAM_TABLE_CAPACITY 512

typedef enum {
        STREAM_OPENING  = 1,
        STREAM_OPEN     = 2,
        STREAM_HALF_TX  = 3,
        STREAM_HALF_RX  = 4,
        STREAM_DEAD     = 5,
} StreamState;

typedef struct {
        u32             id;
        i32             fd;
        StreamState     state;
} Stream;

typedef struct {
        Stream          slots[STREAM_TABLE_CAPACITY];
        u32             next_id;
        pthread_mutex_t lock;
        pthread_cond_t  broadcast;
} StreamTable;

bool stream_table_init(StreamTable *st);
void stream_table_destroy(StreamTable *st);

/*
 * Insert a new stream. Joiner: pass id=0, function allocates and
 * returns the chosen id via *out_id, Host: pass the id received in
 * MSG_PROXY_OPEN; function uses it as-is.
 *
 * Returns true on success, false if the table is full or the host-
 * supplied id is already in use (protocol error - caller should
 * CLOSE the stream and log).
 */
bool stream_table_insert(StreamTable    *st,
                         u32            id,
                         i32            fd,
                         StreamState    initial_state,
                         u32            *out_id);

/*
 * Wait until the stream's state is no longer STREAM_OPENING, or
 * until 'timeout_sec' seconds pass. Returns the final state via
 * *out_state. If the stream disappeared (DEAD reaped), returns
 * STREAM_DEAD. If timeout, returns false.
 */
bool stream_table_wait_open(StreamTable *st,
                        u32             id,
                        int             timeout_sec,
                        StreamState     *out_state);

/*
 * Look up a stream by id. Copies the slot's contents into *out for
 * lock-free use after return. Returns false if not found.
 *
 * Because the copy is a snapshot, callers must not assume the stream
 * still exists when they act on it -- the fd in particular may have
 * been closed by another thread. Use stream_table_transition to
 * make state-dependent changes atomically.
 */
bool stream_table_get(StreamTable *st, u32 id, Stream *out);

/*
 * Atomically transition a stream's state. If the current state is
 * not in 'allowed_from', returns false (caller should treat as
 * protocol error). On STREAM_DEAD transition, the fd is closed
 * and the slot is freed.
 *
 * 'allowed_from' is a bitmask of (1u << state) values.
 */
bool stream_table_transition(StreamTable *st,
                             u32         id,
                             u32         allowed_from,
                             StreamState to);

/*
 * Close all streams. Used at shutdown. Each fd is closed and slots
 * are zeroed.
 */
void stream_table_close_all(StreamTable *st);

#endif
