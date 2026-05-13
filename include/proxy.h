#ifndef PROXY_H
#define PROXY_H

#include "crypto.h"
#include "typedefs.h"

/*
 * proxy.h - SOCKS5 proxy mode over an established P2P session.
 *
 * Replaces chat_run when --proxy is set. The host acts as the exit
 * node; the joiner runs a local SOCKS5 listener on 127.0.0.1:port
 *
 * Trust model: the host sees all of the joiner's non-TLS traffic
 * and is the apparent source IP. Only use between trusting peers.
 */

#define PROXY_DATA_MAX_CHUNK    (32u * KB)
void proxy_run(i32              fd,
               CryptoSession    *s,
               bool             is_host,
               u16              socks_port);

#endif
