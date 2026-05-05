#include "../include/file_offer.h"
#include "../include/logger.h"

#include <string.h>
#include <arpa/inet.h>

static void hton64_pack(u64 host, u8 out[8])
{
        u32 hi = htonl((u32)(host >> 32));
        u32 lo = htonl((u32)(host & 0xFFFFFFFFu));
        memcpy(out,     &hi, 4);
        memcpy(out + 4, &lo, 4);
}

static u64 hton64_unpack(const u8 in[8])
{
        u32 hi, lo;
        memcpy(&hi, in,     4);
        memcpy(&lo, in + 4, 4);
        return ((u64)ntohl(hi) << 32) | (u64)ntohl(lo);
}

bool file_offer_build(const char *name, u64 size,
                      u8 *out_buf, u32 *out_len)
{
        size_t name_len = strlen(name);
        if (name_len == 0 || name_len > FILE_NAME_MAX) {
                log_error("Namelength is not within limits");
                return false;
        }

        hton64_pack(size, out_buf);
        out_buf[8] = (u8)name_len;
        memcpy(out_buf + 9, name, name_len);

        *out_len = (u32)(8 + 1 + name_len);
        return true;
}

bool file_offer_parse(const u8 *payload, u32 len, FileOffer *out)
{
        memset(out, 0, sizeof(*out));
        if (len < 9) {
                log_error("payload size less than minimal size");
                return false;
        }

        u64 size = hton64_unpack(payload);
        u8 name_len = payload[8];
        if (len != (u32)(9 + name_len)) {
                log_error("Declared size and actual size don't match");
                return false;
        }
        if (name_len == 0 || name_len >= FILE_NAME_MAX) {
                log_error("Namelength is not within limits");
                return false;
        }

        memcpy(out->name, payload + 9, name_len);
        out->name[name_len] = '\0';
        out->size = size;
        out->valid = true;
        return true;
}

bool file_offer_sanitize_name(const char *in, char *out, size_t out_size)
{
        if (out_size < 2) return false;

        /*
         * Striop everything up to the last separator. basename() is portable
         * but mutates input on some platforms;
         */
        const char *base = in;
        for (const char *p = in; *p; p++) {
                if (*p == '/' || *p == '\\') base = p + 1;
        }

        if (base[0] == '\0' || base[0] == '.') return false;

        for (const char *p = base; *p; p++) {
                if ((unsigned char)*p < 0x20 || (unsigned char)*p == 0x7f) {
                        return false;
                }
        }

        size_t base_len = strlen(base);
        if (base_len + 1 > out_size || base_len > FILE_NAME_MAX)
                return false;

        memcpy(out, base, base_len + 1);
        return true;
}

void file_offer_format_size(u64 bytes, char *out_buf, size_t out_size)
{
        static const char *units[] = {"B", "KB", "MB", "GB", "TB"};
        double b = (double)bytes;
        int unit = 0;
        while (b >= 1024.0 && unit < 4) { b /= 1024.0; unit++; }
        if (unit == 0)
                snprintf(out_buf, out_size, "%llu B", (unsigned long long)bytes);
        else
                snprintf(out_buf, out_size, "%.1f %s", b, units[unit]);
}
