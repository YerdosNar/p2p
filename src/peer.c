#include <sodium/utils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../include/logger.h"
#include "../include/net.h"
#include "../include/crypto.h"
#include "../include/typedefs.h"
#include "../include/msgtype.h"
#include "../include/identity.h"
#include "../include/room.h"
#include "../include/holepunch.h"

#define DEFAULT_RENDEZVOUS_IP   "127.0.0.1"
#define DEFAULT_RENDEZVOUS_PORT 8888

typedef struct {
        const char      *rendezvous_ip;
        u16             rendezvous_port;
        const char      *identity_path;
        char            role;
        const char      *id;
        const char      *password;
} Args;

static void usage(const char *exe)
{
        printf("Usage: %s --host <id> --password <pw> [options]\n", exe);
        printf("       %s --join <id> --password <pw> [options]\n\n", exe);
        printf("Options:\n");
        printf("  --host <id>             Create a room\n");
        printf("  --join <id>             Join a room\n");
        printf("  --password <pw>         Room password (required, max %d)\n",
               ROOM_PW_MAX);
        printf("  --rendezvous-ip <ip>    Rendezvous server IP (default %s)\n",
               DEFAULT_RENDEZVOUS_IP);
        printf("  --rendezvous-port <p>   Rendezvous server port (default %d)\n",
               DEFAULT_RENDEZVOUS_PORT);
        printf("  --identity <path>       Override identity file location\n");
        printf("  -L, --log-level <lvl>   error|warn|info|debug (default info)\n");
        printf("  -h, --help              Show this help\n");
}

static bool parse_args(int argc, char **argv, Args *a)
{
        memset(a, 0, sizeof(*a));
        a->rendezvous_ip   = DEFAULT_RENDEZVOUS_IP;
        a->rendezvous_port = DEFAULT_RENDEZVOUS_PORT;

        for (int i = 1; i < argc; i++) {
                if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
                        usage(argv[0]); exit(0);
                }
                else if (!strcmp(argv[i], "--host") && i + 1 < argc) {
                        if (a->role) {
                                log_error("--host and --join are mutually exclusive");
                                return false;
                        }
                        a->role = 'H'; a->id = argv[++i];
                }
                else if (!strcmp(argv[i], "--join") && i + 1 < argc) {
                        if (a->role) {
                                log_error("--host and --join are mutually exclusive");
                                return false;
                        }
                        a->role = 'J'; a->id = argv[++i];
                }
                else if (!strcmp(argv[i], "--password") && i + 1 < argc) {
                        a->password = argv[++i];
                }
                else if (!strcmp(argv[i], "--rendezvous-ip") && i + 1 < argc) {
                        a->rendezvous_ip = argv[++i];
                }
                else if (!strcmp(argv[i], "--rendezvous-port") && i + 1 < argc) {
                        a->rendezvous_port = (u16)atoi(argv[++i]);
                }
                else if (!strcmp(argv[i], "--identity") && i + 1 < argc) {
                        a->identity_path = argv[++i];
                }
                else if ((!strcmp(argv[i], "-L") || !strcmp(argv[i], "--log-level"))
                         && i + 1 < argc) {
                        LogLevel lvl;
                        if (logger_parse_level(argv[++i], &lvl))
                                logger_set_level(lvl);
                }
                else {
                        log_error("Unknown argument: %s", argv[i]);
                        return false;
                }
        }

        if (!a->role)             { log_error("Need --host or --join"); return false; }
        if (!a->id)               { log_error("Need room ID");          return false; }
        if (!a->password)         { log_error("Need --password");       return false; }
        if (strlen(a->id) == 0 || strlen(a->id) > ROOM_ID_MAX) {
                log_error("Room ID must be 1..%d chars", ROOM_ID_MAX);
                return false;
        }
        if (strlen(a->password) == 0
            || strlen(a->password) > ROOM_PW_MAX) {
                log_error("Password must be 1..%d chars", ROOM_PW_MAX);
                return false;
        }
        return true;
}

/*
 * Connect to rendezvous on a SO_REUSEPORT-bound local socket.
 *
 * Local port is 0 (kernel-chosen ephemeral). The kernel picks one
 * port for our outgoing connection; that same port becomes the one
 * we report to rendezvous, and (next branch) the one we'll listen
 * on for the incoming peer connection.
 */
static int connect_rendezvous(const char *ip, u16 port)
{
        struct sockaddr_in local = {0};
        local.sin_family      = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port        = 0;

        i32 fd = net_make_bound_socket(&local);
        if (fd == -1) return -1;

        struct sockaddr_in remote = {0};
        remote.sin_family = AF_INET;
        remote.sin_port   = htons(port);
        if (inet_pton(AF_INET, ip, &remote.sin_addr) != 1) {
                log_error("Bad rendezvous IP: %s", ip);
                close(fd);
                return -1;
        }

        if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) == -1) {
                log_error("connect(%s:%u): %s", ip, port, strerror(errno));
                close(fd);
                return -1;
        }
        return fd;
}

/*
 * Run the rendezvous protocol from "connected" through receiving the
 * peer info. Returns true on successful match.
 */
static bool run_rendezvous(int fd, CryptoSession *s, const Args *a,
                           const Identity *id,
                           char *out_peer_ip, u16 *out_peer_port,
                           u8 out_peer_pubkey[IDENTITY_PUBKEY_BYTES])
{
        /* 1. Server sends ROLE_REQ */
        u8 type;
        u8 *payload = NULL;
        u32 plen = 0;
        if (!crypto_recv_typed(fd, &type, &payload, &plen, s)
                        || type != PROTO_ROLE_REQ) {
                log_error("Expected ROLE_REQUEST, got 0x%02x", type);
                free(payload); return false;
        }
        free(payload);

        /* 2. Send our role, ID, password, pubkey */
        if (!crypto_send_typed(fd, PROTO_ROLE_RES,
                               (const u8 *)&a->role, 1, s)) return false;
        if (!crypto_send_typed(fd, PROTO_ROOM_ID,
                               (const u8 *)a->id,
                               (u32)strlen(a->id), s)) return false;
        if (!crypto_send_typed(fd, PROTO_ROOM_PASSWORD,
                               (const u8 *)a->password,
                               (u32)strlen(a->password), s)) return false;
        if (!crypto_send_typed(fd, PROTO_PUBKEY,
                               id->pubkey,
                               IDENTITY_PUBKEY_BYTES, s)) return false;

        log_info("Registered as %s for room '%s'. Waiting for peer...",
                 a->role == 'H' ? "host" : "joiner", a->id);

        /* 3. Wait for PEER_INFO (or PROTO_ERROR) */
        if (!crypto_recv_typed(fd, &type, &payload, &plen, s)) {
                log_error("Connection lost before match");
                return false;
        }
        if (type == PROTO_ERROR) {
                log_error("Rendezvous error: %.*s", (int)plen, payload);
                free(payload);
                return false;
        }
        if (type != PROTO_PEER_INFO) {
                log_error("Expected PEER_INFO, got 0x%02x", type);
                free(payload);
                return false;
        }

        /* Parse [ip_len:1][ip][port:2][pubkey:32] */
        if (plen < 1) { free(payload); return false; }
        u8 ip_len = payload[0];
        u32 expected = 1u + ip_len + 2u + IDENTITY_PUBKEY_BYTES;
        if (plen != expected || ip_len >= INET_ADDRSTRLEN) {
                log_error("Malformed PEER_INFO");
                free(payload);
                return false;
        }

        memcpy(out_peer_ip, payload + 1, ip_len);
        out_peer_ip[ip_len] = '\0';
        u16 port_n;
        memcpy(&port_n, payload + 1 + ip_len, 2);
        *out_peer_port = ntohs(port_n);
        memcpy(out_peer_pubkey, payload + 1 + ip_len + 2, IDENTITY_PUBKEY_BYTES);

        free(payload);
        return true;
}

int main(int argc, char **argv)
{
        Args args;
        if (!parse_args(argc, argv, &args)) {
                fprintf(stderr, "\n");
                usage(argv[0]);
                return 1;
        }

        Identity me;
        if (!identity_load_or_create(&me, args.identity_path)) return 1;

        char fp[IDENTITY_FINGERPRINT_BYTES];
        identity_fingerprint(me.pubkey, fp);
        log_info("My fingerprint: %s", fp);

        i32 fd = connect_rendezvous(args.rendezvous_ip, args.rendezvous_port);
        if (fd == -1) { identity_close(&me); return 1; }

        CryptoSession s;
        if (!crypto_session_handshake(fd, &s)) {
                log_error("Crypto handshake with rendezvous failed");
                close(fd); identity_close(&me); return 1;
        }
        log_debug("Encrypted channel to rendezvous established");

        char peer_ip[INET_ADDRSTRLEN];
        u16  peer_port;
        u8   peer_pubkey[IDENTITY_PUBKEY_BYTES];

        char hex[IDENTITY_PUBKEY_BYTES * 2 + 1];
        sodium_bin2hex(hex, sizeof(hex), peer_pubkey, sizeof(peer_pubkey));
        log_debug("P_PUBKEY before rendezvous: %s", hex);
        bool ok = run_rendezvous(fd, &s, &args, &me,
                                 peer_ip, &peer_port, peer_pubkey);
        sodium_bin2hex(hex, sizeof(hex), peer_pubkey, sizeof(peer_pubkey));
        log_debug("P_PUBKEY after rendezvous: %s", hex);

        crypto_session_close(&s);

        if (!ok) {
                identity_close(&me);
                return 1;
        }

        char peer_fp[IDENTITY_FINGERPRINT_BYTES];
        identity_fingerprint(peer_pubkey, peer_fp);
        log_info("Matched! peer=%s:%u  fingerprint=%s",
                 peer_ip, peer_port, peer_fp);

        // Hole punch, close rendezvous_fd
        i32 p2p_fd = holepunch_to_peer(fd, peer_ip, peer_port);
        if (p2p_fd < 0) {
                log_error("Hole-punch failed - peer unreachable.");
                identity_close(&me);
                return 1;
        }

        // Debuggin purpose only
        {
                char a[65], b[65];
                sodium_bin2hex(a, sizeof(a), me.pubkey, IDENTITY_PUBKEY_BYTES);
                sodium_bin2hex(b, sizeof(b), peer_pubkey, IDENTITY_PUBKEY_BYTES);
                log_debug("auth handshake inputs: \n\tme=%s \n\tpeer=%s", a, b);
        }
        /* ID verification crypto_handshake */
        CryptoSession p2p;
        if (!crypto_session_handshake_authenticated(
                                p2p_fd,
                                me.pubkey, me.seckey,
                                peer_pubkey, &p2p)) {
                log_error("P2P crypto handshake failed.");
                close(p2p_fd);
                identity_close(&me);
                return 1;
        }

        /*
         * Authentication check: send a known-plaintext hello and recv
         * the peer's. If the peer's pubkey was substituted, our session
         * keys differ from theirs and the recv decrypt fails.
         *
         * This proves we're talking to the peer whose fingerprint we
         * trust - not the rendezvous server, not a nework attacker.
         */
        const char *hello_msg = "P2P-HELLO";
        if (!crypto_send_typed(p2p_fd, MSG_CHAT,
                                (const u8 *)hello_msg,
                                (u32)strlen(hello_msg), &p2p)) {
                log_error("Failed to send P2P-HELLO");
                goto p2p_done;
        }

        u8 ht;
        u8 *hp = NULL;
        u32 hl = 0;
        if (!crypto_recv_typed(p2p_fd, &ht, &hp, &hl, &p2p)) {
                log_error("Failed to recvv P2P-HELLO -- "
                          "AUTHENTICATION FAILED. Peer's pubkey may have "
                          "been substituted be MITM");
                goto p2p_done;
        }
        if (ht != MSG_CHAT
            || hl != strlen(hello_msg)
            || memcmp(hp, hello_msg, hl) != 0) {
                log_error("Peer sent unexpected hello: type=0x%02x len=%u",
                                ht, hl);
                free(hp);
                goto p2p_done;
        }
        free(hp);

        log_info("=== P2P Channel established ===");
        log_info("    Peer fingerprint: %s", peer_fp);
        log_info("    Verify this matches what the other side sees as");
        log_info("    THEIR peer's fingerprint, via your shared channel");

p2p_done:
        crypto_session_close(&p2p);
        close(p2p_fd);
        identity_close(&me);
        return ok ? 0 : 1;
}
