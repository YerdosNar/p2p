# OpenP2P Architecture

Reference for understanding the code, written for someone who wants to
modify it. Includes module map, protocol description, threading model,
and security analysis.

## Module map

```
src/
├── logger.c        leveled logger, ANSI colors, TTY-aware
├── net.c           net_recv_all / net_send_all / make_bound_socket
├── crypto.c        X25519 KX + secretstream framing (control + transfer)
├── identity.c      persistent X25519 keypair + fingerprint formatting
├── room.c          rendezvous-side room table (thread-safe)
├── protocol.c      rendezvous-side per-client state machine
├── rendezvous.c    rendezvous main: accept loop + per-client threads
├── holepunch.c     TCP simultaneous-open hole-punch via poll()
├── chat.c          peer-side chat loop: stdin reader + recv thread
├── file_offer.c    file offer wire format + filename sanitization
├── file_stream.c   peer-side file send/receive with TAG_FINAL
├── progress.c      progress bar with throughput, ETA, terminal-width-aware
└── peer.c          peer main: rendezvous flow, handshake, hands off to chat

include/
├── typedefs.h      u8/u16/u32/u64, i8/.../i64, KB/MB/GB
├── msgtype.h       MsgType enum: chat, control, rendezvous, file
└── (header per source file)
```

Two binaries: `rendezvous` links logger+net+crypto+room+protocol+rendezvous,
and `peer` links logger+net+crypto+identity+holepunch+chat+file_offer+
file_stream+progress+peer.

## Layered design

```
┌────────────────────────────────────────────────────────────────┐
│ Application:  chat (chat.c) + file transfer (file_*.c)         │
├────────────────────────────────────────────────────────────────┤
│ Crypto:       crypto.c                                         │
│   - control stream (typed, length-prefixed AEAD frames)        │
│   - transfer stream (untyped, AEAD with TAG_FINAL termination) │
├────────────────────────────────────────────────────────────────┤
│ Net:          net.c   (recv_all, send_all, bound socket)       │
├────────────────────────────────────────────────────────────────┤
│ Kernel TCP                                                     │
└────────────────────────────────────────────────────────────────┘
```

Each layer knows nothing about layers above it. The crypto layer doesn't
know what message types exist; the net layer doesn't know about crypto;
the application layer doesn't manage sockets directly.

## Rendezvous protocol

Both peers connect to the rendezvous. After an anonymous X25519 key
exchange (no identity binding — there's no shared secret yet), all messages
flow over the encrypted control stream.

The rendezvous prompts both peers identically:

```
server → client : PROTO_ROLE_REQ      (no payload)
client → server : PROTO_ROLE_RES      (1 byte: 'H' or 'J')
client → server : PROTO_ROOM_ID       (string, 1-32 chars)
client → server : PROTO_ROOM_PASSWORD (string, 1-32 chars)
client → server : PROTO_PUBKEY        (32 bytes, peer's long-term pubkey)
```

Then the rendezvous either registers the host (waits for joiner) or claims
the room (matches with waiting host). On match:

```
server → both peers : PROTO_PEER_INFO
  payload: [ip_len:1] [ip] [port:2] [pubkey:32]
```

Both peers now know each other's IP, port, and long-term pubkey. They
disconnect from the rendezvous and start the hole-punch.

## Hole-punch

Both peers reuse the same local port they used to talk to the rendezvous
(via `SO_REUSEPORT`). They simultaneously:

- Open a `listen()` socket on that port
- Open a `connect()` socket targeting the peer's advertised IP:port

Whichever resolves first wins. The other socket is closed. This is TCP
simultaneous-open and works on most consumer NATs (cone NATs, port-restricted
cone NATs). Symmetric NATs typically defeat it.

After the punch, both sides have a TCP connection to each other.

## Identity-verifying P2P handshake

Anonymous KX wouldn't help here: a malicious rendezvous could substitute
its own pubkey in `PROTO_PEER_INFO` and MITM. So the P2P handshake binds
both **ephemeral** and **long-term** keys into the session derivation:

```
both sides:
  - generate ephemeral X25519 keypair
  - exchange ephemeral pubkeys
  - role = sign(memcmp(my_long_pk, peer_long_pk))
  - k1 = kx(my_ephem,  peer_ephem)   # forward secrecy
  - k2 = kx(my_long,   peer_long)    # authentication
  - session_key = blake2b(sort(k1.rx, k1.tx, k2.rx, k2.tx))
```

If the peer's `peer_long_pk` was substituted at rendezvous time, the
attacker can't compute the legitimate `k2`, so the session keys diverge.
The first encrypted message (`P2P-HELLO`) fails to decrypt and the
connection is rejected.

The handshake itself doesn't fail on a wrong long_pk — the divergence
shows up when the receiver's secretstream init succeeds but the first
pull returns "forged or corrupted." That's the actual MITM detector.

## Wire formats

### Control stream

Bidirectional secretstream. Each frame:

```
[ length:     u32 network-order   ]   ciphertext length
[ ciphertext: length bytes        ]   plaintext_len + 17
```

Plaintext layout:

```
[ type:    u8                     ]   MsgType enum
[ payload: ...                    ]   type-specific
```

Type 0x00 reserved (never sent; an all-zero plaintext is invalid).\
Types 0x01–0x0F: app-layer (chat, BYE).\
Types 0x10–0x1F: rendezvous protocol.\
Types 0x20–0x2F: file transfer.

`crypto_send_typed` / `crypto_recv_typed` in `crypto.c` handle this
framing.

### Transfer stream

Per-file ephemeral secretstream. Created at the start of each transfer,
terminated by `TAG_FINAL` on the last chunk. Same frame structure as the
control stream, but the plaintext has **no type byte** — the only thing
on a transfer stream is file data.

Multiplexing: strict alternation. While a transfer is active, the control
stream is paused. After `TAG_FINAL` plus `MSG_TRANSFER_DONE` (sent over
the control stream), both sides return to control-stream mode.

### File transfer flow

```
sender → recv : MSG_FILE_OFFER       [size:8][name_len:1][name]
recv   → sender: MSG_FILE_ACCEPT     (or _REJECT, no payload)
sender → recv : MSG_TRANSFER_HEADER  [key:32][header:24]
                                      both for the new transfer stream
sender → recv : <chunks on transfer stream> ... TAG_FINAL
recv   → sender: MSG_TRANSFER_DONE   (no payload, on control stream)
```

## Threading model

### Rendezvous server

- Main thread: `accept()` loop, spawns one thread per client.
- Per-client thread: detached. Runs `crypto_session_handshake` then
  `protocol_handle_client`. Lives until the client's protocol exchange
  finishes (host case: thread exits when the host registers; the host's
  fd lives on in the room table). Client threads communicate only via the
  shared `RoomTable` (mutex-protected).
- Sweep: piggybacks on `accept()` loop, runs at the start of each accept.
  No dedicated sweeper thread.

### Peer

- Main thread (= "send thread"): reads stdin char-by-char, dispatches
  commands, calls `crypto_send_typed` for chat messages.
- Recv thread: detached. Blocks on `crypto_recv_typed`. Dispatches by
  message type. During an outgoing transfer, this thread *also* drives
  the file send loop (it's already where ACCEPT arrives, so it's the
  natural owner). During an incoming transfer, it drives the receive
  loop.

Two mutexes:

- `g_input_lock`: the in-progress input buffer + transfer state machine
- `g_io_lock`: serializes all stdout writes

Lock order: input first, then io. Always.

### Why no thread-per-direction during transfers

Because the strict-alternation multiplexing means while transfer is
active, no other messages flow. The recv thread runs the transfer in its
own context. The send thread sees `XFER_ACTIVE` and silently drops input.

This breaks if we ever wanted background transfers (chat continuing
while a file moves), which would require multiplexing with a stream-id
byte rather than strict alternation.

## Identity persistence

Long-term keys are stored at `$XDG_CONFIG_HOME/openp2p/identity.key`
(or `~/.config/openp2p/identity.key`). Format: 64 raw bytes — 32 public
followed by 32 secret. Permissions enforced as 0600 (matches SSH).

`identity_load_or_create` is a load-or-generate primitive: if the file
exists and is well-formed, load it; if it doesn't exist, generate a new
keypair and save it. Corrupted files are NOT auto-regenerated — the
function refuses to start, requiring user intervention. This protects
against silently losing identity to a transient I/O error.

## Key cryptographic primitives

| Purpose                    | Primitive                          |
|----------------------------|------------------------------------|
| Key exchange               | X25519 (libsodium `crypto_kx`)     |
| AEAD                       | XChaCha20-Poly1305 (secretstream)  |
| Key derivation (combine kx)| BLAKE2b (libsodium `generichash`)  |
| Constant-time compare      | `sodium_memcmp`                    |
| Memory zeroing             | `sodium_memzero`                   |

All keys, ephemeral and long-term, are zeroed before exit and on error
paths. Stack buffers holding key material use `sodium_memzero`.

## What this codebase does not do

- IPv6 (only AF_INET hard-coded; would require parallel paths in
  net.c and protocol.c)
- TURN-style relay (no fallback when hole-punch fails)
- Persistent message history (intentionally — no on-disk storage of chat)
- Out-of-order chunks (transfer is strictly sequential)
- Resumable transfers (a killed transfer starts over)

## Testing strategy

`make asan` builds with AddressSanitizer + stack-protector. Run the full
end-to-end flow under ASAN before merging any change to the protocol or
the threading model. Bugs that survive non-instrumented builds (the
identity-fingerprint heisenbug, for example) often reveal themselves
immediately under ASAN.

Manual end-to-end test: rendezvous + two peers, exchange chat messages,
exchange a multi-MB file, verify byte-exact match via `sha256sum` on
both sides.

There is no automated test suite. Adding one is the next step after
documentation (see `feat/test-harness` or similar).
