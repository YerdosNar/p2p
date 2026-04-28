#ifndef ROOM_H
#define ROOM_H

#include "crypto.h"

#include <netinet/in.h>
#include <pthread.h>

/*
 * room.h - thread-safe room table.
 *
 * Public functions take/return enough state for protocol.c to act on
 * a room without holding the table lock, Internal locking is hidden;
 * callers never see the mutex.
 *
 * Limits (final-form values; extend later as needed):
 */
#define ROOM_ID_MAX      32
#define ROOM_DEFAULT_MAX 5000

/*
 * One slot in the table. is_active is the only "is this slot in use"
 * marker - there's no separate free list. find_free_slot just scans
 * for !is_active.
 */
typedef struct {
        char            room_id[ROOM_ID_MAX + 1];
        char            host_ip[INET_ADDRSTRLEN];
        u16             host_port;
        i32             host_fd;
        u8              host_pubkey[CRYPTO_PUBKEYB];
        CryptoSession   host_session;
        time_t          created_at;
        bool            is_active;
} Room;

typedef struct {
        Room            *rooms;
        u32             capacity;
        pthread_mutex_t lock;
} RoomTable;

/*
 * Initialize *rt with room for 'capacity' rooms.
 * On success: true
 * On failure: *rt is left in a state safe to ignore
 *                 (no mutex created, no memory allocated).
 */
bool room_table_init(RoomTable *rt, u32 capacity);

void room_table_destroy(RoomTable *rt);

/*
 * Register a host atomically: check that 'id' is unique, find a free
 * slot, fill it in, mark active.
 *
 * On success: returns the slot index (>= 0)
 * On failure: returns -1 and *err_msg points to a static reason string
 *             ("ID already in use", "table full"). The caller should
 *             forward *err_msg to the client as a PROTO_ERROR.
 *
 * Takes ownership of the host_session (copies it in). Does not take
 * ownership of host_fd; that fd lives in the table until a joiner
 * claims it or the room is otherwise removed.
 */
int room_register_host(
                RoomTable           *rt,
                const char          *id,
                const char          *host_ip,
                const u16           host_port,
                i32                 host_fd,
                const u8            host_pubkey[CRYPTO_PUBKEYB],
                const CryptoSession *host_session,
                const char          **err_msg);

/*
 * Claim a room for joiner. Looks up by id, copies the host's data
 * into the output parameters, and marks the slot inactive.
 *
 * On success: returns true; out_* are filled.
 * On failure: return false; and *err_msg is set.
 */
bool room_claim(RoomTable       *rt,
                const char      *id,
                char            *out_host_ip,
                u16             *out_host_port,
                i32             *out_host_fd,
                u8              out_host_pubkey[CRYPTO_PUBKEYB],
                CryptoSession   *out_host_session,
                const char      **err_msg);

/* Print "active/capacity" to log_info. */
void room_print_stats(RoomTable *rt);

#endif
