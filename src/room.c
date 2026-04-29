#include "../include/room.h"
#include "../include/logger.h"

#include <stdlib.h>
#include <string.h>

static int find_free_slot(const RoomTable *rt)
{
        for (u32 i = 0; i < rt->capacity; i++) {
                if (!rt->rooms[i].is_active) return (int)i;
        }
        return -1;
}

static Room *find_by_id(RoomTable *rt, const char *id)
{
        for (u32 i = 0; i < rt->capacity; i++) {
                if (!rt->rooms[i].is_active) continue;
                if (!strcmp(rt->rooms[i].room_id, id))
                        return &rt->rooms[i];
        }
        return NULL;
}

bool room_table_init(RoomTable *rt, u32 capacity)
{
        memset(rt, 0, sizeof(RoomTable));

        rt->rooms = calloc(capacity, sizeof(Room));
        if (!rt->rooms) return false;

        if (pthread_mutex_init(&rt->lock, NULL) != 0) {
                free(rt->rooms);
                rt->rooms = NULL;
                return false;
        }
        rt->capacity = capacity;
        return true;
}

void room_table_destroy(RoomTable *rt)
{
        if (!rt || !rt->rooms) return;
        for (u32 i = 0; i < rt->capacity; i++) {
                if (rt->rooms[i].is_active)
                        sodium_memzero(rt->rooms[i].password,
                                        sizeof(rt->rooms[i].password));
        }
        free(rt->rooms);
        pthread_mutex_destroy(&rt->lock);
        memset(rt, 0, sizeof(*rt));
}

int room_register_host(
                RoomTable           *rt,
                const char          *id,
                const char          *password,
                const char          *host_ip,
                const u16           host_port,
                i32                 host_fd,
                const u8            host_pubkey[CRYPTO_PUBKEYB],
                const CryptoSession *host_session,
                const char          **err_msg)
{
        size_t id_len = strlen(id);
        if (id_len == 0 || id_len > ROOM_ID_MAX) {
                *err_msg = "ID length out of range";
                return -1;
        }
        size_t pw_len = strlen(password);
        if (pw_len == 0 || pw_len > ROOM_PW_MAX) {
                *err_msg = "Password length out of range";
                return -1;
        }

        pthread_mutex_lock(&rt->lock);

        if (find_by_id(rt, id) != NULL) {
                pthread_mutex_unlock(&rt->lock);
                *err_msg = "ID already in use";
                return -1;
        }

        int slot = find_free_slot(rt);
        if (slot < 0) {
                pthread_mutex_unlock(&rt->lock);
                *err_msg = "Server at maximum capacity";
                return -1;
        }

        Room *r = &rt->rooms[slot];
        memset(r, 0, sizeof(*r));

        strncpy(r->room_id, id, ROOM_ID_MAX);
        r->room_id[ROOM_ID_MAX] = '\0';
        strncpy(r->password, password, ROOM_PW_MAX);
        r->password[ROOM_PW_MAX] = '\0';

        strncpy(r->host_ip, host_ip, sizeof(r->host_ip) - 1);
        r->host_port = host_port;
        r->host_fd   = host_fd;
        memcpy(r->host_pubkey, host_pubkey, CRYPTO_PUBKEYB);
        r->host_session = *host_session;
        r->created_at   = time(NULL);
        r->is_active    = true;

        pthread_mutex_unlock(&rt->lock);
        return slot;
}

bool room_claim(RoomTable       *rt,
                const char      *id,
                const char      *attempted_password,
                char            *out_host_ip,
                u16             *out_host_port,
                i32             *out_host_fd,
                u8              out_host_pubkey[CRYPTO_PUBKEYB],
                CryptoSession   *out_host_session,
                const char      **err_msg)
{
        pthread_mutex_lock(&rt->lock);

        Room *r = find_by_id(rt, id);
        if (!r) {
                pthread_mutex_unlock(&rt->lock);
                log_debug("claim: no room with id '%s'", id);
                *err_msg = "No such room";
                return false;
        }

        size_t stored_len = strlen(r->password);
        size_t attempted_len = strlen(attempted_password);

        bool ok = (stored_len == attempted_len) &&
                  (sodium_memcmp(r->password,
                                 attempted_password,
                                 stored_len) == 0);

        if (!ok) {
                pthread_mutex_unlock(&rt->lock);
                log_debug("claim: bad password for '%s'", id);
                *err_msg = "Authentication failed";
                return false;
        }

        strncpy(out_host_ip, r->host_ip, INET_ADDRSTRLEN - 1);
        out_host_ip[INET_ADDRSTRLEN - 1] = '\0';
        *out_host_port  = r->host_port;
        *out_host_fd    = r->host_fd;
        memcpy(out_host_pubkey, r->host_pubkey, CRYPTO_PUBKEYB);
        *out_host_session = r->host_session;

        sodium_memzero(r->password, sizeof(r->password));
        r->is_active = false;

        pthread_mutex_unlock(&rt->lock);
        return true;
}

void room_print_stats(RoomTable *rt)
{
        pthread_mutex_lock(&rt->lock);
        u32 active = 0;
        for (u32 i = 0; i < rt->capacity; i++) {
                if (rt->rooms[i].is_active) active++;
        }
        u32 cap = rt->capacity;
        pthread_mutex_unlock(&rt->lock);

        log_info("Active rooms: %u / %u", active, cap);
}
