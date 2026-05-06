# OpenP2P Usage

## Programs

OpenP2P consists of two binaries:

- **`rendezvous`** — the matchmaking server. Listens for peers, introduces
  them, then steps out of the way. Stateless across restarts; no persistent
  data.
- **`peer`** — the user-facing program. Connects to a rendezvous, finds the
  other peer, establishes a direct encrypted connection, runs a chat with
  optional file transfer.

## `rendezvous` flags
```ascii
./rendezvous [options]
-p, --port <port>        Listening port (default: 8888)
-m, --max-rooms <n>      Max concurrent rooms (default: 5000)
-L, --log-level <lvl>    error | warn | info | debug (default: info)
-h, --help               Show help
```

The rendezvous holds rooms in memory only. Rooms expire 5 minutes after
creation if no joiner has arrived. Restarting the server drops all pending
rooms; pending peers will see "Connection lost."

There is no authentication for *running* a rendezvous (anyone who connects
can register a room). Authentication is per-room, via password, between
peers.

## `peer` flags
```ascii
./peer --host <id> --password <pw> [options]
./peer --join <id> --password <pw> [options]
Required (one of):
--host <id>              Create a room with this ID
--join <id>              Join the room with this ID
Required:
--password <pw>          Room password (1-32 chars)
Common options:
--rendezvous-ip <ip>     Rendezvous server IP (default: 127.0.0.1)
--rendezvous-port <p>    Rendezvous server port (default: 8888)
--identity <path>        Override identity file location
-L, --log-level <lvl>    error | warn | info | debug (default: info)
-h, --help               Show help
```

`--password` accepts any string up to 32 characters. The password is sent
to the rendezvous over an encrypted channel; it never appears on the wire
in plaintext. However, a malicious rendezvous can attempt to crack it
offline if the password is weak — use a passphrase, not "1234."

## Chat commands

Once connected:

```ascii
hello                    plain message, sent to peer
/send /tmp/photo.jpg     initiate file transfer
/quit                    end the session
Ctrl-D                   same as /quit (when prompt is empty)
Ctrl-C                   interrupt; restores terminal but ends process
```
During an incoming file transfer offer, the prompt changes to:
`Accept file 'photo.jpg' (2.3 MB)? [y/n]: `

Type `y` or `n` and press Enter. Any other response re-prompts.

During an active transfer (sending or receiving), keystrokes are silently
dropped. Wait for the transfer to complete; chat resumes automatically.

## Common scenarios

### Two friends, talking for the first time

1. Friend A sets up a rendezvous on a VPS, or both agree on a public one.
2. They agree on a room ID and password over a side channel
   (text message, phone call).
3. A starts: `./peer --host alice-bob --password our-secret --rendezvous-ip <ip>`
4. B starts: `./peer --join alice-bob --password our-secret --rendezvous-ip <ip>`
5. **Both verify each other's fingerprint over the side channel.** If
   fingerprints match, the connection is secure.

After the first session, A's and B's identity keys are persisted. On
subsequent sessions, if the fingerprints differ from what they remember,
something has changed (key file deleted, new machine, or attacker —
investigate).

### Sending a large file

```bash
/send /home/me/Videos/recording.mp4
Waiting for peer to accept 'recording.mp4' (3.2 GB)...
```

(peer accepts)
```bash
Peer accepted. Sending 'recording.mp4'...
Sending [████████░░░░░░░░░░░░] 42% — 1.3 GB / 3.2 GB — 8.4 MB/s — ETA 3m 45s
```
The receiver sees the file appear in their current working directory. If
`recording.mp4` already exists there, OpenP2P writes `recording_1.mp4`,
`recording_2.mp4`, etc.

### Multiple peers on the same machine

For testing, run two peers locally with separate identity files:
```bash
./peer --host test --password test --rendezvous-ip 127.0.0.1 --identity /tmp/peerA.key
```
in another terminal:
```bash
./peer --join test --password test --rendezvous-ip 127.0.0.1 --identity /tmp/peerB.key
```
>Without `--identity`, both peers read the same default file and would have
identical keys.

## Troubleshooting

### "Hole-punch failed — peer unreachable"

The most common cause is a *symmetric NAT* on one or both ends. Symmetric
NATs assign different external ports per destination, defeating the
hole-punch trick. Possible workarounds:

- Move one peer to a different network (mobile data instead of office WiFi
  often helps)
- Run both peers on networks behind cone NATs (most home routers)
- Run one peer on a public IP

This branch does not include a TURN-style relay fallback.

### "Authentication failed"

Either the room ID doesn't exist (wrong ID, expired, or peer hasn't
registered yet) or the password is wrong. The rendezvous returns the same
error in both cases on purpose — it doesn't leak which.

If you're sure both fields are right, check:

- TTL: rooms expire 5 minutes after the host registers. If the joiner
  takes longer, the room is gone. Re-register on the host side.
- Whitespace: passwords are matched exactly. Trailing newlines or stray
  spaces from copy-paste cause silent failures.

### "secretstream_pull failed"

Indicates a decryption failure during the P2P handshake or transfer. Two
common causes:

- Pubkey substitution (MITM attempt). Verify peer fingerprints
  out-of-band; if they don't match, the rendezvous is hostile.
- Software bug. If fingerprints match, you've found one — please report.

### Identity file permissions error
`[x] Identity file ... is accessible to group/other (mode 0644).`

OpenP2P refuses to load identity files with permissive permissions, the
same way SSH refuses world-readable private keys. Fix:
```bash
chmod 600 ~/.config/openp2p/identity.key
```

### Terminal looks broken after Ctrl-C

If a peer is killed via `kill -9` (or any signal that bypasses our
cleanup), the terminal can be left in raw mode. To fix:
```bash
reset
# (or `stty sane`).
```

## Logging

```ascii
`-L debug` prints every protocol step. Useful for diagnosing handshake
failures or unexpected behavior. Useful debug log signposts:
[d] Generated ephemeral X25519 keypair.
[d] kx role: CLIENT          (or SERVER -- decided by pubkey comparison)
[d] Derived shared symmetric key.
[d] Secretstream initialized in both directions.
[d] Encrypted channel to rendezvous established
[d] Local port for hole-punch: 45153
```
Errors and warnings go to stderr; informational messages go to stdout.
You can redirect them separately:
```bash
./peer ... > out.log 2> err.log
```
