#include "../include/proxy.h"
#include "../include/logger.h"

#include <unistd.h>

void proxy_run(i32              fd,
               CryptoSession    *s,
               bool             is_host,
               u16              socks_port)
{
        (void)fd; (void)s;

        if (is_host) {
                log_info("Proxy mode: acting as EXIT NODE for peer.");
        } else {
                log_info("Proxy mode: routing local traffic through peer.");
                log_info("Proxy mode: listen port %u", socks_port);
        }
        log_warn("proxy_run is a stub; exiting");
}
