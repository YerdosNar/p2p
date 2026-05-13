#include "../include/stream_table.h"
#include "../include/logger.h"

#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

bool stream_table_init(StreamTable *st)
{
        memset(st, 0, sizeof(StreamTable));
        if (pthread_mutex_init(&st->lock, NULL) != 0) return false;
        if (pthread_cond_init (&st->broadcast, NULL) != 0) {
                pthread_mutex_destroy(&st->lock);
                return false;
        }
        st->next_id = 1;
        return true;
}

void stream_table_destroy(StreamTable *st)
{
        stream_table_close_all(st);
        pthread_cond_destroy(&st->broadcast);
        pthread_mutex_destroy(&st->lock);
}

static Stream *find_slot_by_id(StreamTable *st, u32 id)
{
        for (u32 i = 0; i < STREAM_TABLE_CAPACITY; i++)
                if (st->slots[i].id == id) return &st->slots[i];
        return NULL;
}

static Stream *find_free_slot(StreamTable *st)
{
        return find_slot_by_id(st, 0);
}

bool stream_table_wait_open(StreamTable *st,
                        u32             id,
                        int             timeout_sec,
                        StreamState     *out_state)
{
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += timeout_sec;

        pthread_mutex_lock(&st->lock);
        log_debug("wait_open(%u): entering wait", id);
        for (;;) {
                Stream *slot = NULL;
                for (u32 i = 0; i < STREAM_TABLE_CAPACITY; i++)
                        if (st->slots[i].id == id) {slot=&st->slots[i];break;}
                if (!slot) {
                        log_debug("wait_open(%u): slot gone -> DEAD", id);
                        *out_state = STREAM_DEAD;
                        pthread_mutex_unlock(&st->lock);
                        return true;
                }
                if (slot->state != STREAM_OPENING) {
                        log_debug("wait_open(%u): state=%d, returning", id, slot->state);
                        *out_state = slot->state;
                        pthread_mutex_unlock(&st->lock);
                        return true;
                }
                int rc = pthread_cond_timedwait(&st->broadcast,
                                                &st->lock, &deadline);
                log_debug("wait_open(%u): cond returned rc=%d (state=%d)",
                          id, rc, slot->state);
                if (rc == ETIMEDOUT) {
                        pthread_mutex_unlock(&st->lock);
                        return false;
                }
        }
}

bool stream_table_insert(StreamTable *st, u32 id, i32 fd, StreamState initial_state, u32 *out_id)
{
        pthread_mutex_lock(&st->lock);

        u32 assigned;
        if (id == 0) {
                assigned = st->next_id++;
                if (assigned == 0) assigned = st->next_id++;
        } else {
                if (find_slot_by_id(st, id) != NULL) {
                        pthread_mutex_unlock(&st->lock);
                        log_warn("stream %u: duplicate insert", id);
                        return false;
                }
                assigned = id;
        }

        Stream *slot = find_free_slot(st);
        if (!slot) {
                pthread_mutex_unlock(&st->lock);
                log_warn("stream table full (cap=%u)",
                         STREAM_TABLE_CAPACITY);
                return false;
        }

        slot->id        = assigned;
        slot->fd        = fd;
        slot->state     = initial_state;

        if (out_id) *out_id = assigned;
        pthread_mutex_unlock(&st->lock);
        return true;
}

bool stream_table_get(StreamTable *st, u32 id, Stream *out)
{
        if (id == 0) return false;
        pthread_mutex_lock(&st->lock);
        Stream *slot = find_slot_by_id(st, id);
        if (slot) *out = *slot;
        pthread_mutex_unlock(&st->lock);
        return slot != NULL;
}

bool stream_table_transition(StreamTable *st, u32 id, u32 allowed_from, StreamState to)
{
        if (id == 0) return false;
        pthread_mutex_lock(&st->lock);

        Stream *slot = find_slot_by_id(st, id);
        if (!slot) {
                pthread_mutex_unlock(&st->lock);
        }
        if (!(allowed_from & (1u << slot->state))) {
                log_warn("stream %u: illegal transition %d -> %d",
                         id, slot->state, to);
                pthread_mutex_unlock(&st->lock);
                return false;
        }

        StreamState from_state = slot->state;
        slot->state = to;
        if (to == STREAM_DEAD) {
                if (slot->fd >= 0) close(slot->fd);
                memset(slot, 0, sizeof(*slot));
        }
        log_debug("transition(%u): %d -> %d, broadcasting",
                  id, from_state, to);
        pthread_cond_destroy(&st->broadcast);
        pthread_mutex_unlock(&st->lock);
        return true;
}

void stream_table_close_all(StreamTable *st)
{
        pthread_mutex_lock(&st->lock);
        for (u32 i = 0; i < STREAM_TABLE_CAPACITY; i++) {
                if (st->slots[i].id == 0) continue;
                if (st->slots[i].fd >= 0) close(st->slots[i].fd);
                memset(&st->slots[i], 0, sizeof(st->slots[i]));
        }
        pthread_mutex_unlock(&st->lock);
}
