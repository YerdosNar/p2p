#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/logger.h"
#include "../include/net.h"
#include "../include/crypto.h"
#include "../include/typedefs.h"
#include "../include/msgtype.h"
#include "../include/identity.h"
#include "../include/room.h"

#define DEFAULT_RENDEZVOUS_IP   "103.115.18.208"
#define DEFAULT_RENDEZVOUS_PORT 888

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

static bool parse(int argc, char **argv, Args *a)
{
        memset(a, 0, sizeof(*a));
        a->rendezvous_ip = DEFAULT_RENDEZVOUS_IP;
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
