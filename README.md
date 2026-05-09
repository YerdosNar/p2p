# OpenP2P

End-to-end encrypted peer-to-peer chat and file transfer over the public
internet. Two friends share a room ID and password, and OpenP2P does the rest:
NAT traversal, identity verification, encrypted chat, encrypted file transfer.

No central server stores messages. The rendezvous server only introduces peers
to each other; it cannot decrypt or read any traffic.

## Features

- End-to-end encryption (X25519 + XChaCha20-Poly1305 via libsodium)
- Hole-punching through most consumer NATs
- Persistent identity keys with verifiable fingerprints
- Authenticated handshake (resists man-in-the-middle by the rendezvous)
- Live file transfers with progress, resume-on-collision, ETA
- Forward secrecy: past sessions remain confidential if long-term keys leak

## Building

Requirements:

- Linux (tested on Arch and Termux/Android)
- gcc with C11 support
- libsodium (`apt install libsodium-dev`, `pacman -S libsodium`, etc.)
- pthreads (standard on Linux)

```bash
make            # builds rendezvous + peer with -O2
make debug      # -O0 -g for gdb
make asan       # -O0 -g + AddressSanitizer; use before merging changes
make clean      # just clean, nothing else...
```

Output binaries: `./rendezvous` and `./peer`.

## Quick start

You need a rendezvous server reachable by both peers. Two options:

**Option A: run your own** (recommended for testing or private use)

```bash
# On a VPS or any machine reachable by both peers:
./rendezvous --port 8888
```

**Option B: use a public rendezvous**

If a public OpenP2P rendezvous server exists, point both peers at tis address.
Note that any rendezvous server can attempt to MITM the initial handshake;
**always verify peer fingerprints out-of-band** when using a rendezvous you don't control. (See "Security model" below)

Once a rendezvous is reachable, on the host side:
```bash
./peer --host alice --password coffee --rendezvous-ip <some-ip>
```

On the joiner side:
```bash
./peer --join alice --password coffee --rendezvous-ip <some-ip>
```

After the handshake completes, both peers see:
```ascii
=== P2P Channel established ===
Peer fingerprint: 8f3a 92b1 c4d7 e8f0
Chatting with peer (fingerprint 8f3a 92b1 c4d7 e8f0).
/quit       end the session
/send PATH  send a file
```

Type freely. `/send /path/to/file.pdf` initiates a file transfer; the peer
gets a y/n prompt. `/quit` or Ctrl-D ends the session.

## Verifying your peer

The fingerprint shown after connection is derived from your peer's long-term
public key. To confirm you're talking to the right person and not an attacker
substituting their own key at the rendezvous:

1. Read your fingerprint to your peer over a separate channel (phone call,
   in person, signed message).
2. Have them confirm their fingerprint matches what your terminal shows under
   "Peer fingerprint."
3. If they match, the channel is end-to-end secure.
4. If they don't, abort: someone is in the middle.

Long-term keys are stored at `$XDG_CONFIG_HOME/openp2p/identity.key` (or
`~/.config/openp2p/identity.key`). The same key persists across sessions, so
fingerprints stay stable.

## Security model

OpenP2P provides:

- Confidentiality and integrity of all traffic between peers
- Identity verification (when fingerprints are confirmed out-of-band)
- Forward secrecy — past sessions stay private even if your long-term key
  later leaks
- The rendezvous server cannot decrypt traffic between peers
- Limited brute-force protection: rooms are killed after 5 wrong
  password attempts. Attackers can still mount distributed attacks
  by retrying with new room IDs, but the per-room budget is small.

OpenP2P does **not** protect against:

- A malicious rendezvous denying the introduction (it can simply refuse)
- A malicious rendezvous attempting MITM if users skip fingerprint
  verification on first contact
- Compromise of either peer's machine
- Traffic analysis (an observer can see *that* two peers are communicating,
  even though they cannot read what they say)

This is a hobby project, not a hardened communication tool. For threats above
"casual eavesdropping," use Signal.

## Documentation

- [USAGE.md](USAGE.md) — full flag reference, common scenarios, troubleshooting
- [ARCHITECTURE.md](ARCHITECTURE.md) — code structure, protocol, threading
  model — read this before modifying the code

## License

MIT — see [LICENSE](LICENSE).
