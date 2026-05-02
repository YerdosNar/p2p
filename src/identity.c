#include "../include/identity.h"
#include "../include/logger.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define IDENTITY_FILENAME "identity.key"
#define IDENTITY_FILE_SIZE (IDENTITY_PUBKEY_BYTES + IDENTITY_SECKEY_BYTES)

static char *default_config_dir(void)
{
        const char *xdg = getenv("XDG_CONFIG_HOME");
        const char *home = getenv("HOME");
        char *out = NULL;

        if (xdg && xdg[0] != '\0') {
                size_t n = strlen(xdg) + strlen("/openp2p") + 1;
                out = malloc(n);
                if (out) snprintf(out, n, "%s/openp2p", xdg);
                return out;
        }

        if (!home) {
                struct passwd *pw = getpwuid(getuid());
                if (!pw || !pw->pw_dir) return NULL;
                home = pw->pw_dir;
        }

        size_t n = strlen(home) + strlen("/.config/openp2p") + 1;
        out = malloc(n);
        if (out) snprintf(out, n, "%s/.config/openp2p", home);
        return out;
}

static bool mkdir_p_0700(const char *path)
{
        char *tmp = strdup(path);
        if (!tmp) return false;
        size_t len = strlen(tmp);
        if (len == 0) { free(tmp); return false; }

        for (size_t i = 1; i < len; i++) {
                if (tmp[i] != '/') continue;
                tmp[i] = '\0';
                if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
                        log_error("mkdir(%s): %s", tmp, strerror(errno));
                        free(tmp);
                        return false;
                }
                tmp[i] = '/';
        }
        if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
                log_error("mkdir(%s): %s", tmp, strerror(errno));
                free(tmp);
                return false;
        }
        free(tmp);
        return true;
}

/*
 * Verify file permissions are 0600 exactly.
 * If the file is readable by group or other == data leak.
 */
static bool check_perms(const char *path)
{
        struct stat st;
        if (stat(path, &st) != 0) {
                log_error("stat(%s): %s", path, strerror(errno));
                return false;
        }
        if (st.st_mode & (S_IRWXG | S_IRWXO)) {
                log_error("Identity file %s is accessible by group/other "
                          "(mode %04o). Run: chmod 600 %s",
                          path, st.st_mode & 07777, path);
                return false;
        }

        return true;
}

static bool load_existing(const char *path, Identity *out)
{
        if (!check_perms(path)) return false;

        i32 fd = open(path, O_RDONLY);
        if (fd < 0) {
                log_error("open(%s): %s", path, strerror(errno));
                return false;
        }

        u8 buf[IDENTITY_FILE_SIZE];
        size_t total = 0;
        while (total < (size_t)sizeof(buf)) {
                size_t r = read(fd, buf + total, sizeof(buf) - total);
                if (r > 0) { total += r; continue; }
                if (r == 0) break;
                if (errno == EINTR) continue;
                log_error("read(%s): %s", path, strerror(errno));
                close(fd);
                sodium_memzero(buf, sizeof(buf));
                return false;
        }
        close(fd);

        if (total != (ssize_t)sizeof(buf)) {
                log_error("Identity file %s has wrong size (%zd, expected %zu). "
                          "If corrupted, delete to regenerate.",
                          path, total, sizeof(buf));
                sodium_memzero(buf, sizeof(buf));
                return false;
        }

        memcpy(out->pubkey, buf, IDENTITY_PUBKEY_BYTES);
        memcpy(out->seckey, buf + IDENTITY_PUBKEY_BYTES, IDENTITY_SECKEY_BYTES);
        sodium_memzero(buf, sizeof(buf));
        return true;
}

static bool save_new(const char *path, const Identity *id)
{
        /*
         * O_CREAT | O_EXCL | O_WRONLY with mode 0600. The exclusive
         * create prevents a TOCTOU between "does the file exist?"
         * and "create it." If two peers race to create, one wins.
         */
        i32 fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (fd < 0) {
                log_error("open(%s) for write: %s", path, strerror(errno));
                return false;
        }

        u8 buf[IDENTITY_FILE_SIZE];
        memcpy(buf, id->pubkey, IDENTITY_PUBKEY_BYTES);
        memcpy(buf + IDENTITY_PUBKEY_BYTES, id->seckey, IDENTITY_SECKEY_BYTES);

        ssize_t total = 0;
        while (total < (ssize_t)sizeof(buf)) {
                ssize_t w = write(fd, buf + total, sizeof(buf) - total);
                if (w > 0) {total += w; continue;}
                if (errno == EINTR) continue;
                log_error("write(%s): %s", path, strerror(errno));
                close(fd);
                unlink(path); // no partial file
                sodium_memzero(buf, sizeof(buf));
                return false;
        }

        sodium_memzero(buf, sizeof(buf));
        if (close(fd) != 0) {
                log_error("close(%s): %s", path, strerror(errno));
                unlink(path);
                return false;
        }
        return true;
}

bool identity_load_or_create(Identity *out, const char *path)
{
        if (sodium_init() < 0) {
                log_error("sodium_init() failed");
                return false;
        }
        memset(out, 0, sizeof(*out));

        char *resolved_path = NULL;
        char *resolved_dir  = NULL;

        if (path) {
                resolved_path = strdup(path);
                if (!resolved_path) return false;
        } else {
                resolved_dir = default_config_dir();
                if (!resolved_dir) {
                        log_error("Cannot determine config directory "
                                  "(no $HOME, no $XDG_CONFIG_HOME).");
                        return false;
                }
                if (!mkdir_p_0700(resolved_dir)) {
                        free(resolved_dir);
                        return false;
                }
                size_t n = strlen(resolved_dir) + strlen("/" IDENTITY_FILENAME) + 1;
                resolved_path = malloc(n);
                if (!resolved_path) { free(resolved_dir); return false; }
                snprintf(resolved_path, n, "%s/%s", resolved_dir, IDENTITY_FILENAME);
        }

        if (access(resolved_path, F_OK) == 0) {
                bool ok = load_existing(resolved_path, out);
                if (ok) log_info("Loaded identity from %s", resolved_path);
                free(resolved_path);
                free(resolved_dir);
                return ok;
        }

        crypto_kx_keypair(out->pubkey, out->seckey);
        if (!save_new(resolved_path, out)) {
                sodium_memzero(out, sizeof(*out));
                free(resolved_path);
                free(resolved_dir);
                return false;
        }
        log_info("Generated new identity at %s", resolved_path);
        free(resolved_path);
        free(resolved_dir);
        return true;
}

void identity_fingerprint(const u8 public_key[IDENTITY_PUBKEY_BYTES],
                          char out_buf[IDENTITY_FINGERPRINT_BYTES])
{
        static const char hex[] = "0123456789abcdef";
        char *p = out_buf;
        for (i32 g = 0; g < 4; g++) {
                for (i32 b = 0; b < 2; b++) {
                        u8 byte = public_key[g * 2 + b];
                        *p++ = hex[byte >> 4];
                        *p++ = hex[byte & 0x0f];
                }
                if (g < 3) *p++ = ' ';
        }
        *p = '\0';
}

void identity_close(Identity *id)
{
        if (!id) return;
        sodium_memzero(id->seckey, sizeof(id->seckey));
        sodium_memzero(id->pubkey, sizeof(id->pubkey));
}
