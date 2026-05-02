#include "../include/protocol.h"
#include "../include/msgtype.h"
#include "../include/logger.h"
#include "../include/typedefs.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sodium.h>

/*
 * Send a PROTO_ERROR message and close the fd.
 */
static void send_error_and_close(i32 fd, CryptoSession *s, const char *msg)
{
        log_warn("Protocol error: %s", msg);
        crypto_send_typed(fd, PROTO_ERROR,
                         (const u8 *)msg, (u32)strlen(msg), s);
        close(fd);
}

/*
 * Build and send a PROTO_PEER_INFO message.
 * Layout: [ip_len][ip][port:2][pubkey:32]
 */
static bool send_peer_info(
                i32             fd,
                CryptoSession   *s,
                const char      *peer_ip,
                u16             peer_port,
                const u8        peer_pubkey[CRYPTO_PUBKEYB])
{
        size_t ip_len = strlen(peer_ip);
        if (ip_len > 0xff) {
                /* INET_ADDRSTRLEN is 16, but the length-prefix is one byte
                 * and we want to be honest */
                log_error("peer_ip too long for length-prefix encoding");
                return false;
        }

        u8 buf[1 + 0xff + 2 + CRYPTO_PUBKEYB];
        size_t pos = 0;

        buf[pos++] = (u8)ip_len;
        memcpy(buf + pos, peer_ip, ip_len);
        pos += ip_len;

        u16 port_n = htons(peer_port);
        memcpy(buf + pos, &port_n, sizeof(port_n));
        pos += sizeof(port_n);

        memcpy(buf + pos, peer_pubkey, CRYPTO_PUBKEYB);
        pos += CRYPTO_PUBKEYB;

        return crypto_send_typed(fd, PROTO_PEER_INFO, buf, (u32)pos, s);
}

/*
 * Read one message of the expected type. Frees the payload after copying
 * it out via *out_data / *out_len (heap; caller must free).
 *
 * Returns false (and logs) if recv fails or the type doesn't match.
 */
static bool recv_expected(
                i32             fd,
                CryptoSession   *s,
                u8              expected_type,
                u8              **out_data,
                u32             *out_len)
{
        u8 type;
        u8 *data = NULL;
        u32 len = 0;
        if (!crypto_recv_typed(fd, &type, &data, &len, s)) return false;

        if (type != expected_type) {
                log_warn("Expected type 0x%02x, got 0x%02x", expected_type, type);
                free(data);
                return false;
        }
        *out_data = data;
        *out_len  = len;
        return true;
}

/*
 * Host flow:
 *      recv ROOM_ID
 *      read peer's pubkey out of the session struct -
 */
static void handle_host(
                i32             fd,
                const char      *client_ip,
                u16             client_port,
                CryptoSession   *session,
                RoomTable       *rt)
{
        u8 *id_payload = NULL;
        u32 id_len = 0;
        if (!recv_expected(fd, session, PROTO_ROOM_ID, &id_payload, &id_len)) {
                close(fd);
                return;
        }
        /* id_payload is NUL-terminated by crypto_recv_typed. */
        char id[ROOM_ID_MAX + 1];
        if (id_len == 0 || id_len > ROOM_ID_MAX) {
                free(id_payload);
                send_error_and_close(fd, session, "Bad room ID length");
                return;
        }
        memcpy(id, id_payload, id_len);
        id[id_len] = '\0';
        free(id_payload);

        u8 *pw_payload = NULL;
        u32 pw_len = 0;
        if (!recv_expected(fd, session, PROTO_ROOM_PASSWORD,
                                &pw_payload, &pw_len)) {
                close(fd); return;
        }
        if (pw_len == 0 || pw_len > ROOM_PW_MAX) {
                free(pw_payload);
                send_error_and_close(fd, session, "Bad password length");
                return;
        }
        char password[ROOM_PW_MAX + 1];
        memcpy(password, pw_payload, pw_len);
        password[pw_len] = '\0';
        sodium_memzero(pw_payload, pw_len);
        free(pw_payload);

        /* Receive the host's pubkey - 32 bytes wrapped in a typed */
        u8 *pk_payload = NULL;
        u32 pk_len = 0;
        u8 pk_type = 0;
        if (!crypto_recv_typed(fd, &pk_type, &pk_payload, &pk_len, session)) {
                close(fd); return;
        }
        if (pk_type != PROTO_PUBKEY || pk_len != CRYPTO_PUBKEYB) {
                free(pk_payload);
                send_error_and_close(fd, session, "Expected pubkey");
                return;
        }
        u8 host_pubkey[CRYPTO_PUBKEYB];
        memcpy(host_pubkey, pk_payload, sizeof(host_pubkey));
        free(pk_payload);

        const char *err = NULL;
        int slot = room_register_host(
                        rt, id, password,
                        client_ip, client_port,
                        fd, host_pubkey,
                        session, &err);
        sodium_memzero(password, sizeof(password));
        if (slot < 0) {
                send_error_and_close(fd, session, err);
                return;
        }

        log_info("Host '%s' registered in slot %d (waiting for joiner)",
                        id, slot);
}

static void handle_joiner(
                i32             fd,
                const char      *client_ip,
                u16             client_port,
                CryptoSession   *session,
                RoomTable       *rt)
{
        // Receive ID
        u8 *id_payload = NULL;
        u32 id_len = 0;
        if (!recv_expected(fd, session, PROTO_ROOM_ID, &id_payload, &id_len)) {
                close(fd);
                return;
        }
        char id[ROOM_ID_MAX + 1];
        if (id_len == 0 || id_len > ROOM_ID_MAX) {
                free(id_payload);
                send_error_and_close(fd, session, "Bad room ID length");
                return;
        }
        memcpy(id, id_payload, id_len);
        id[id_len] = '\0';
        free(id_payload);

        // Receive PW
        u8 *pw_payload = NULL;
        u32 pw_len = 0;
        if (!recv_expected(fd, session, PROTO_ROOM_PASSWORD, &pw_payload, &pw_len)) {
                close(fd);
                return;
        }
        char pw[ROOM_PW_MAX + 1];
        if (pw_len == 0 || pw_len > ROOM_PW_MAX) {
                free(pw_payload);
                send_error_and_close(fd, session, "Bad room password length");
                return;
        }
        memcpy(pw, pw_payload, pw_len);
        pw[pw_len] = '\0';
        free(pw_payload);

        /* Receive joiner's pubkey */
        u8 *pk_payload = NULL;
        u32 pk_len = 0;
        u8 pk_type = 0;
        if (!crypto_recv_typed(fd, &pk_type, &pk_payload, &pk_len, session)) {
                close(fd); return;
        }
        if (pk_type != PROTO_PUBKEY || pk_len != CRYPTO_PUBKEYB) {
                free(pk_payload);
                send_error_and_close(fd, session, "Expected pubkey");
                return;
        }
        u8 joiner_pubkey[CRYPTO_PUBKEYB];
        memcpy(joiner_pubkey, pk_payload, sizeof(joiner_pubkey));
        free(pk_payload);

        /* Atomically claim the room */
        char    host_ip[INET_ADDRSTRLEN];
        u16     host_port;
        i32     host_fd;
        u8      host_pubkey[CRYPTO_PUBKEYB];
        CryptoSession host_session;
        const char *err = NULL;

        if (!room_claim(rt, id, pw,
                        host_ip, &host_port, &host_fd,
                        host_pubkey, &host_session, &err)) {
                send_error_and_close(fd, session, err);
                return;
        }

        log_info("Match: '%s' [%s:%u] joining host [%s:%u]",
                 id, client_ip, client_port, host_ip, host_port);

        /* Tell host about joiner */
        if (!send_peer_info(host_fd, &host_session,
                            client_ip, client_port, joiner_pubkey)) {
                log_warn("Failed to deliver peer info to host");
        }

        /* Tell joiner about host */
        if (!send_peer_info(fd, session,
                            host_ip, host_port, host_pubkey)) {
                log_warn("Failed to deliver peer info to joiner");
        }

        sodium_memzero(&host_session, sizeof(host_session));
        close(host_fd);
        close(fd);
}

void protocol_handle_client(
                i32             fd,
                const char      *client_ip,
                u16             client_port,
                CryptoSession   *session,
                RoomTable       *rt)
{
        /* Send role request */
        if (!crypto_send_typed(fd, PROTO_ROLE_REQ, NULL, 0, session)) {
                log_warn("Failed to send role request");
                close(fd);
                return;
        }

        /* Receive role response (one byte: 'H' or 'J') */
        u8 *role_payload = NULL;
        u32 role_len = 0;
        if (!recv_expected(fd, session, PROTO_ROLE_RES,
                                &role_payload, &role_len)) {
                close(fd);
                return;
        }
        if (role_len != 1) {    // it shoudl be exactly 1 byte
                free(role_payload);
                send_error_and_close(fd, session, "Bad role length");
                return;
        }

        u8 role = role_payload[0];
        free(role_payload);

        if (role == 'H' || role == 'h') {
                handle_host(fd, client_ip, client_port, session, rt);
        } else if (role == 'J' || role == 'j') {
                handle_joiner(fd, client_ip, client_port, session, rt);
        } else {
                send_error_and_close(fd, session, "Unknown role");
        }
}
