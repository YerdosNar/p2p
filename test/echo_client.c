/*
 * test/echo_client.c
 *
 * Test client for the rendezvous server. Plays either role:
 *
 *   ./test/echo_client --host <id>   creates room <id>
 *   ./test/echo_client --join <id>   joins room <id>
 *
 * On success: prints the matched peer's IP:port and pubkey hash, exit 0.
 * On any protocol or crypto error, exit non-zero.
 *
 * Two instances on localhost should match. Host blocks on accept of
 * peer info; joiner triggers the match.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sodium.h>

#include "../include/logger.h"
#include "../include/crypto.h"
#include "../include/msgtype.h"

static int connect_to(const char *ip, uint16_t port)
{
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) { log_error("socket()"); return -1; }
        struct sockaddr_in sa = {0};
        sa.sin_family      = AF_INET;
        sa.sin_addr.s_addr = inet_addr(ip);
        sa.sin_port        = htons(port);
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
                log_error("connect() to %s:%u failed", ip, port);
                close(fd);
                return -1;
        }
        return fd;
}

/*
 * Run the H/J protocol up through PROTO_PEER_INFO. Prints the peer's
 * info and returns 0 on success.
 */
static int run_role(const char *ip, uint16_t port, char role, const char *id, const char *password)
{
        int fd = connect_to(ip, port);
        if (fd == -1) return 1;

        CryptoSession s;
        if (!crypto_session_handshake(fd, &s)) {
                log_error("Handshake failed");
                close(fd);
                return 1;
        }
        log_info("Handshake OK");

        /* 1. Server sends PROTO_ROLE_REQUEST */
        uint8_t  type;
        uint8_t *payload = NULL;
        uint32_t plen = 0;
        if (!crypto_recv_typed(fd, &type, &payload, &plen, &s)
            || type != PROTO_ROLE_REQ) {
                log_error("Expected ROLE_REQUEST, got 0x%02x", type);
                free(payload); close(fd); return 1;
        }
        free(payload);

        /* 2. Send PROTO_ROLE_RESPONSE */
        if (!crypto_send_typed(fd, PROTO_ROLE_RES,
                               (const uint8_t *)&role, 1, &s)) {
                close(fd); return 1;
        }

        /* 3. Send PROTO_ROOM_ID */
        if (!crypto_send_typed(fd, PROTO_ROOM_ID,
                               (const uint8_t *)id, (uint32_t)strlen(id), &s)) {
                close(fd); return 1;
        }

        /* 4. Send PROTO_ROOM_PASSWORD */
        if (!crypto_send_typed(fd, PROTO_ROOM_PASSWORD,
                               (const u8 *)password,
                               (u32)strlen(password), &s)) {
                close(fd); return 1;
        }

        /* 5. Send PROTO_PUBKEY (32 bytes -- a fake one for the test) */
        uint8_t my_fake_pubkey[crypto_kx_PUBLICKEYBYTES];
        randombytes_buf(my_fake_pubkey, sizeof(my_fake_pubkey));
        if (!crypto_send_typed(fd, PROTO_PUBKEY,
                               my_fake_pubkey, sizeof(my_fake_pubkey), &s)) {
                close(fd); return 1;
        }
        log_info("Sent role=%c id=%s pubkey=%02x%02x%02x...",
                 role, id, my_fake_pubkey[0], my_fake_pubkey[1], my_fake_pubkey[2]);

        /* 5. Wait for PROTO_PEER_INFO (server sends after match) */
        log_info("Waiting for match...");
        if (!crypto_recv_typed(fd, &type, &payload, &plen, &s)) {
                log_error("Connection lost while waiting for peer info");
                close(fd); return 1;
        }
        if (type == PROTO_ERROR) {
                log_error("Server error: %.*s", (int)plen, payload);
                free(payload); close(fd); return 1;
        }
        if (type != PROTO_PEER_INFO) {
                log_error("Expected PEER_INFO, got 0x%02x", type);
                free(payload); close(fd); return 1;
        }

        /* Parse peer info: [ip_len][ip][port:2][pubkey:32] */
        if (plen < 1) { free(payload); close(fd); return 1; }
        uint8_t ip_len = payload[0];
        if (plen != (uint32_t)(1 + ip_len + 2 + crypto_kx_PUBLICKEYBYTES)) {
                log_error("Malformed PEER_INFO");
                free(payload); close(fd); return 1;
        }
        char     peer_ip[64] = {0};
        memcpy(peer_ip, payload + 1, ip_len);
        uint16_t peer_port_n;
        memcpy(&peer_port_n, payload + 1 + ip_len, 2);
        uint16_t peer_port = ntohs(peer_port_n);
        const uint8_t *peer_pk = payload + 1 + ip_len + 2;

        log_info("Matched! peer=%s:%u pubkey=%02x%02x%02x...",
                 peer_ip, peer_port, peer_pk[0], peer_pk[1], peer_pk[2]);

        free(payload);
        crypto_session_close(&s);
        close(fd);
        return 0;
}

int main(int argc, char **argv)
{
        const char *ip = "127.0.0.1";
        uint16_t port = 8888;
        char role = 0;
        const char *id = NULL;
        const char *password = NULL;

        for (int i = 1; i < argc; i++) {
                if (!strcmp(argv[i], "--host") && i + 1 < argc) {
                        role = 'H'; id = argv[++i];
                }
                else if (!strcmp(argv[i], "--join") && i + 1 < argc) {
                        role = 'J'; id = argv[++i];
                }
                else if (!strcmp(argv[i], "--password") && i + 1 < argc) {
                        password = argv[++i];
                }
                else if (!strcmp(argv[i], "--ip") && i + 1 < argc) {
                        ip = argv[++i];
                }
                else if (!strcmp(argv[i], "--port") && i + 1 < argc) {
                        port = (uint16_t)atoi(argv[++i]);
                }
                else if (!strcmp(argv[i], "-L") && i + 1 < argc) {
                        LogLevel lvl;
                        if (logger_parse_level(argv[++i], &lvl))
                                logger_set_level(lvl);
                }
                else {
                        fprintf(stderr,
                                "usage: %s [--host|--join] <id> [--ip IP] [--port N]\n",
                                argv[0]);
                        return 1;
                }
        }
        if (!role || !id) {
                fprintf(stderr, "must specify --host <id> or --join <id>\n");
                return 1;
        }
        if (!password) {
                fprintf(stderr, "must specify --password <pw>\n");
                return 1;
        }

        return run_role(ip, port, role, id, password);
}
