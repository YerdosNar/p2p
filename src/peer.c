#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
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
#include "../include/chat.h"
#include "../include/proxy.h"

#define DEFAULT_RENDEZVOUS_IP           "127.0.0.1"
#define DEFAULT_RENDEZVOUS_DNAME        "localhost"
#define DEFAULT_RENDEZVOUS_PORT         8888
#define DEFAULT_PROXY_PORT              1080

typedef struct {
        char            rendezvous_host[256];
        u16             rendezvous_port;
        const char      *identity_path;
        char            role;
        char            name[32];
        const char      *id;
        const char      *password;
        bool            proxy;
        u16             socks_port;
} Args;

// Globally accessible
static Args args;

static void usage(const char *exe)
{
        printf("Usage: %s --host <id> --password <pw> [options]\n", exe);
        printf("       %s --join <id> --password <pw> [options]\n\n", exe);
        printf("Options:\n");
        printf("  -H, --host <id>             Create a room\n");
        printf("  -J, --join <id>             Join a room\n");
        printf("  -P, --password <pw>         Room password (required, max %d)\n",
               ROOM_PW_MAX);
        printf("  -n, --name <name>           Set name at the start (default role-based)\n");
        printf("  -r, --rendezvous            Rendezvous server host or IP (default %s)\n", DEFAULT_RENDEZVOUS_IP);
        printf("  -i, --rendezvous-ip <ip>    Deprecated alias for --rendezvous\n");
        printf("  -d, --domain <domain>       Deprecated alias for --rendezvous\n");
        printf("  -p, --rendezvous-port <p>   Rendezvous server port (default %d)\n",
               DEFAULT_RENDEZVOUS_PORT);
        printf("  --identity <path>           Override identity file location\n");
        printf("  --proxy                     Runs SOCKS5 (host=EXIT node)\n");
        printf("  --socks-port <p>            Local SOCKS5 port for joiner (default %u)\n",
               DEFAULT_PROXY_PORT);
        printf("  -L, --log-level <lvl>       error|warn|info|debug (default info)\n");
        printf("  -h, --help                  Show this help\n");
}

static bool parse_args(int argc, char **argv)
{
        args.socks_port = DEFAULT_PROXY_PORT;
        strncpy(args.rendezvous_host,
                DEFAULT_RENDEZVOUS_IP,
                sizeof(args.rendezvous_host) - 1);
        args.rendezvous_host[INET_ADDRSTRLEN-1] = '\0';
        args.rendezvous_port = DEFAULT_RENDEZVOUS_PORT;

        for (int i = 1; i < argc; i++) {
                if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
                        usage(argv[0]); exit(0);
                }
                else if ((!strncmp(argv[i], "-H", 2)
                                || !strncmp(argv[i], "--host", 6))
                                && i + 1 < argc) {
                        if (i != 1) {
                                log_warn("%s flag should be at the very front",
                                                argv[i]);
                        }
                        if (args.role) {
                                log_error("--host and --join are mutually exclusive");
                                return false;
                        }
                        args.role = 'H'; args.id = argv[++i];
                }
                else if ((!strncmp(argv[i], "-J", 2)
                                || !strncmp(argv[i], "--join", 6))
                                && i + 1 < argc) {
                        if (i != 1) {
                                log_warn("%s flag should be at the very front",
                                                argv[i]);
                        }
                        if (args.role) {
                                log_error("--host and --join are mutually exclusive");
                                return false;
                        }
                        args.role = 'J'; args.id = argv[++i];
                }
                else if ((!strncmp(argv[i], "-P", 2)
                                || !strcmp(argv[i], "--password"))
                                && i + 1 < argc) {
                        args.password = argv[++i];
                }
                else if (!strncmp(argv[i], "-n", 2)
                                || !strncmp(argv[i], "--name", 6)) {
                        char *role_based_name = (args.role == 'H') ? "Host"
                                                                  : "Join";
                        strncpy(args.name, role_based_name, sizeof(args.name));
                        if (i + 1 < argc) {
                                strncpy(args.name, argv[++i], sizeof(args.name)-1);
                                args.name[sizeof(args.name) - 1] = '\0';
                        } else {
                                log_warn("%s flag needs string", argv[i]);
                        }
                        log_info("Name: %s", args.name);
                }
                else if ((!strncmp(argv[i], "-r", 2)
                                || !strcmp(argv[i], "--rendezvous"))
                                && i + 1 < argc) {
                        strncpy(args.rendezvous_host, argv[++i],
                                sizeof(args.rendezvous_host) - 1);
                        args.rendezvous_host[sizeof(args.rendezvous_host) - 1] = '\0';
                }
                else if ((!strncmp(argv[i], "-i", 2)
                                || !strcmp(argv[i], "--rendezvous-ip"))
                                && i + 1 < argc) {
                        log_warn("--rendezvous-ip is deprecated; "
                                 "use --rendezvous");
                        strncpy(args.rendezvous_host, argv[++i],
                                sizeof(args.rendezvous_host) - 1);
                        args.rendezvous_host[sizeof(args.rendezvous_host) - 1] = '\0';
                }
                else if ((!strncmp(argv[i], "-d", 2)
                                || !strncmp(argv[i], "--domain", 8))
                                && i + 1 < argc) {
                        log_warn("--domain is deprecated;"
                                 "use --rendezvous");
                        strncpy(args.rendezvous_host, argv[++i],
                                sizeof(args.rendezvous_host) - 1);
                        args.rendezvous_host[sizeof(args.rendezvous_host) - 1] = '\0';
                }
                else if (!strcmp(argv[i], "--proxy")) {
                        args.proxy = true;
                }
                else if (!strcmp(argv[i], "--socks-port")
                                && i + 1 < argc
                                && args.role == 'J'
                                && args.proxy) {
                        int p = atoi(argv[++i]);
                        if (p <= 1024 || p > 65535) {
                                log_warn("Invalid port '%s'; using %d.",
                                         argv[i], DEFAULT_PROXY_PORT);
                                continue;
                        }
                        args.socks_port = p;
                }
                else if ((!strncmp(argv[i], "-p", 2)
                                || !strcmp(argv[i], "--rendezvous-port"))
                                && i + 1 < argc) {
                        int p = atoi(argv[++i]);
                        if (p <= 1024 || p > 65535) {
                                log_warn("Invalid port '%s'; using %d.",
                                         argv[i], DEFAULT_RENDEZVOUS_PORT);
                                continue;
                        }
                        args.rendezvous_port = p;
                }
                else if (!strcmp(argv[i], "--identity") && i + 1 < argc) {
                        args.identity_path = argv[++i];
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

        if (!args.role)             { log_error("Need --host or --join"); return false; }
        if (!args.id)               { log_error("Need room ID");          return false; }
        if (!args.password)         { log_error("Need --password");       return false; }
        if (strlen(args.id) == 0 || strlen(args.id) > ROOM_ID_MAX) {
                log_error("Room ID must be 1..%d chars", ROOM_ID_MAX);
                return false;
        }
        if (strlen(args.password) == 0
            || strlen(args.password) > ROOM_PW_MAX) {
                log_error("Password must be 1..%d chars", ROOM_PW_MAX);
                return false;
        }
        return true;
}

/*
 * Connect to the rendezvous. 'host' may be an IPv4 literal, IPv6
 * literal, or hostname. Tries all addresses returned by getaddrinfo
 * in order.
 *
 * On success: returns fd and writes the resolved family to *out_family.
 * On failure: returns -1.
 */
static int connect_rendezvous(const char *host, u16 port, u8 *out_family)
{
        struct addrinfo hints = {0};
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags    = AI_ADDRCONFIG;

        char portstr[8];
        snprintf(portstr, sizeof(portstr), "%u", port);

        struct addrinfo *res = NULL;
        int rc = getaddrinfo(host, portstr, &hints, &res);
        if (rc != 0 || !res) {
                log_error("getaddrinfo(%s): %s", host, gai_strerror(rc));
                return -1;
        }

        i32 fd = -1;
        for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
                struct sockaddr_storage local = {0};
                socklen_t local_len = 0;
                if (ai->ai_family == AF_INET) {
                        struct sockaddr_in *sa  = (struct sockaddr_in *)&local;
                        sa->sin_family          = AF_INET;
                        sa->sin_addr.s_addr     = htonl(INADDR_ANY);
                        sa->sin_port            = 0;
                        local_len               = sizeof(*sa);
                } else if (ai->ai_family == AF_INET6) {
                        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)&local;
                        sa->sin6_family         = AF_INET6;
                        sa->sin6_addr           = in6addr_any;
                        sa->sin6_port           = 0;
                        local_len               = sizeof(*sa);
                } else {
                        continue;
                }

                fd = net_make_bound_socket((const struct sockaddr *)&local,
                                           local_len);
                if (fd < 0) continue;

                if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
                        char ipstr[INET6_ADDRSTRLEN] = {0};
                        if (ai->ai_family == AF_INET) {
                                struct sockaddr_in *sa = (struct sockaddr_in *)
                                                         ai->ai_addr;
                                inet_ntop(AF_INET, &sa->sin_addr,
                                          ipstr, sizeof(ipstr));
                                *out_family = 4;
                        } else {
                                struct sockaddr_in6 *sa = (struct sockaddr_in6 *)
                                                          ai->ai_addr;
                                inet_ntop(AF_INET6, &sa->sin6_addr,
                                          ipstr, sizeof(ipstr));
                                *out_family = 6;
                        }
                        log_info("Connected to rendezvous %s (IPv%u)",
                                        ipstr, *out_family);
                        freeaddrinfo(res);
                        return fd;
                }

                log_debug("connect to one address failed: %s", strerror(errno));
                close(fd);
                fd = -1;
        }

        freeaddrinfo(res);
        log_error("All rendezvous adresses failed for '%s'", host);
        return -1;
}

/*
 * Run the rendezvous protocol from "connected" through receiving the
 * peer info. Returns true on successful match.
 */
static bool run_rendezvous(int fd, CryptoSession *s,
                           const Identity *id,
                           char *out_peer_ip, u16 *out_peer_port,
                           u8 *out_peer_family,
                           u8 out_peer_pubkey[IDENTITY_PUBKEY_BYTES])
{
        u8 type;
        u8 *payload = NULL;
        u32 plen;
        /* 1. Server sends ROLE_REQ */
        if (!crypto_recv_typed(fd, &type, &payload, &plen, s)
                        || type != PROTO_ROLE_REQ) {
                log_error("Expected ROLE_REQUEST, got 0x%02x", type);
                free(payload); return false;
        }
        free(payload);
        payload = NULL;

        /* 2. Send our role, ID, password, pubkey */
        if (!crypto_send_typed(fd, PROTO_ROLE_RES,
                               (const u8 *)&args.role, 1, s)) return false;
        if (!crypto_send_typed(fd, PROTO_ROOM_ID,
                               (const u8 *)args.id,
                               (u32)strlen(args.id), s)) return false;
        if (!crypto_send_typed(fd, PROTO_ROOM_PASSWORD,
                               (const u8 *)args.password,
                               (u32)strlen(args.password), s)) return false;
        if (!crypto_send_typed(fd, PROTO_PUBKEY,
                               id->pubkey,
                               IDENTITY_PUBKEY_BYTES, s)) return false;

        log_info("Registered as %s for room '%s'. Waiting for peer...",
                 args.role == 'H' ? "host" : "joiner", args.id);

        for (;;) {
                if (!crypto_recv_typed(fd, &type, &payload, &plen, s)) {
                        log_error("Connection lost before match");
                        return false;
                }
                if (type != PROTO_WARN) break;

                log_warn("Rendezvous warning: %.*s", (int)plen, payload);
                free(payload);
                payload = NULL;
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

        /* Parse [family:1][ip_len:1][ip][port:2][pubkey:32] */
        if (plen < 2) { free(payload); return false; }
        u8 family = payload[0];
        u8 ip_len = payload[1];
        u32 expected = 2u + ip_len + 2u + IDENTITY_PUBKEY_BYTES;
        if (plen != expected || ip_len >= INET6_ADDRSTRLEN) {
                log_error("Malformed PEER_INFO");
                free(payload);
                return false;
        }
        if (family != 4 && family != 6) {
                log_error("PEER_INFO: unknown family %u", family);
                free(payload);
                return false;
        }

        memcpy(out_peer_ip, payload + 2, ip_len);
        out_peer_ip[ip_len] = '\0';
        u16 port_n;
        memcpy(&port_n, payload + 2 + ip_len, 2);
        *out_peer_port = ntohs(port_n);
        memcpy(out_peer_pubkey,
               payload + 2 + ip_len + 2,
               IDENTITY_PUBKEY_BYTES);
        *out_peer_family = family;

        free(payload);
        return true;
}

static bool check_fingerprint(i32 fd, CryptoSession *s)
{
        const char *hello_msg = "P2P-HELLO";
        if (!crypto_send_typed(fd, MSG_CHAT,
                                (const u8 *)hello_msg,
                                (u32)strlen(hello_msg), s)) {
                log_error("Failed to send P2P-HELLO");
                return false;
        }

        u8 ht;
        u8 *hp = NULL;
        u32 hl = 0;
        if (!crypto_recv_typed(fd, &ht, &hp, &hl, s)) {
                log_error("Failed to recv P2P-HELLO -- "
                          "AUTHENTICATION FAILED. Peer's pubkey may have "
                          "been substituted be MITM");
                return false;
        }
        if (ht != MSG_CHAT
            || hl != strlen(hello_msg)
            || memcmp(hp, hello_msg, hl) != 0) {
                log_error("Peer sent unexpected hello: type=0x%02x len=%u",
                                ht, hl);
                free(hp);
                return false;
        }
        free(hp);
        return true;
}

static bool name_exchange(
                i32             fd,
                char            *out_peer_name,
                CryptoSession   *s)
{
        if (!crypto_send_typed(fd, MSG_NAME,
                                (const u8 *)args.name,
                                (u32)strlen(args.name), s)) {
                log_error("Failed to send our my_name");
                return false;
        }

        u8 type;
        u8 *name_payload = NULL;
        u32 len;
        if (!crypto_recv_typed(fd, &type, &name_payload, &len, s)) {
                log_error("Failed to recv peer name");
                return false;
        }
        if (type != MSG_NAME) {
                log_error("Peer sent unexpected type: type=0x%02x", type);
                return false;
        }
        if (len == 0) {
                log_error("Empty name");
        }
        if (len > 31) {
                log_warn("Name is longer than the buffer: "
                         "Will be truncated");
                len = 31;
        }
        memcpy(out_peer_name, (const char*)name_payload, len);
        out_peer_name[len] = '\0';

        free(name_payload);
        name_payload = NULL;

        return true;
}

static bool mode_agree(i32 fd, CryptoSession *s)
{
        u8 my_mode = args.proxy ? 'P' : 'C';
        if (!crypto_send_typed(fd, MSG_MODE, &my_mode, 1, s)) {
                log_error("Failed to send mode");
                return false;
        }

        u8 type;
        u8 *payload;
        u32 plen;
        if (!crypto_recv_typed(fd, &type, &payload, &plen, s)) {
                log_error("Failed to recv peer mode");
                return false;
        }
        if (type != MSG_MODE || plen != 1) {
                log_error("Expected MSG_MODE (plen 1), got 0x%02x (plen %u)",
                          type, plen);
                free(payload);
                return false;
        }

        u8 peer_mode = payload[0];
        free(payload);

        if (peer_mode != 'C' && peer_mode != 'P') {
                log_error("Peer sent unknown mode byte 0x%02x", peer_mode);
                return false;
        }

        if (peer_mode != my_mode) {
                log_error("Mode mismatch: we want '%s', peer wants '%s'. "
                          "Both sides must pass (or omit) --proxy",
                          (my_mode == 'C') ? "CHAT" : "PROXY",
                          (peer_mode == 'C') ? "CHAT" : "PROXY");
                return false;
        }
        log_info("Mode agreed %s", args.proxy ? "PROXY" : "CHAT");
        return true;
}

int main(int argc, char **argv)
{
        memset(&args, 0, sizeof(Args));
        if (!parse_args(argc, argv)) {
                fprintf(stderr, "\n");
                usage(argv[0]);
                return 1;
        }

        Identity me;
        if (!identity_load_or_create(&me, args.identity_path)) return 1;

        char fp[IDENTITY_FINGERPRINT_BYTES];
        identity_fingerprint(me.pubkey, fp);
        log_info("My fingerprint: %s", fp);

        u8 rendezvous_family;
        i32 fd = connect_rendezvous(args.rendezvous_host,
                                    args.rendezvous_port,
                                    &rendezvous_family);
        if (fd == -1) { identity_close(&me); return 1; }

        CryptoSession s;
        if (!crypto_session_handshake(fd, &s)) {
                log_error("Crypto handshake with rendezvous failed");
                close(fd); identity_close(&me); return 1;
        }
        log_debug("Encrypted channel to rendezvous established");

        char peer_ip[INET6_ADDRSTRLEN];
        u16  peer_port;
        u8   peer_family;
        u8   peer_pubkey[IDENTITY_PUBKEY_BYTES];

        bool ok = run_rendezvous(fd, &s, &me,
                                 peer_ip, &peer_port,
                                 &peer_family,
                                 peer_pubkey);

        crypto_session_close(&s);

        if (!ok) {
                identity_close(&me);
                return 1;
        }

        char peer_fp[IDENTITY_FINGERPRINT_BYTES];
        identity_fingerprint(peer_pubkey, peer_fp);
        log_info("Matched! peer=%s:%u (IPv%u) fingerprint=%s",
                 peer_ip, peer_port, peer_family, peer_fp);

        // Hole punch, close rendezvous_fd
        i32 p2p_fd = holepunch_to_peer(fd, peer_ip, peer_port,
                                       peer_family, rendezvous_family);
        if (p2p_fd < 0) {
                log_error("Hole-punch failed - peer unreachable.");
                identity_close(&me);
                return 1;
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
        if (!check_fingerprint(p2p_fd, &p2p)) {
                log_error("check_fingerprint failed");
                goto p2p_done;
        }

        if (!mode_agree(p2p_fd, &p2p)) {
                log_error("Mode agreement failed");
                goto p2p_done;
        }

        // Exchange names
        if (args.name[0] == '\0') {
                printf("Enter your name: ");
                fgets(args.name, sizeof(args.name), stdin);
                net_strip_newline(args.name);
        }
        char peer_name[32];
        if (!name_exchange(p2p_fd, peer_name, &p2p)) {
                log_error("name_exchange failed");
                goto p2p_done;
        }

        printf("\033[2J\033[H");
        log_info("=== P2P Channel established ===");
        log_info("    Peer fingerprint: %s", peer_fp);
        log_info("    Peer name       : %s", peer_name);

        if (args.proxy) {
                proxy_run(p2p_fd, &p2p, args.role == 'H', args.socks_port);
        } else {
                chat_run(p2p_fd, &p2p, peer_fp,
                         (const char*)peer_name,
                         (const char*)args.name);
        }
        goto p2p_done;

p2p_done:
        crypto_session_close(&p2p);
        close(p2p_fd);
        identity_close(&me);
        return ok ? 0 : 1;
}
