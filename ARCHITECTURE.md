# Architecture

This is a peer-to-peer file sharing agent. Two people run their own copy of
this agent on their own machines. One person shares a file, the other person
downloads it, and the bytes go straight from one machine to the other. There
is no server holding the file in the middle.

The thing that makes it different from ordinary file sharing is that a peer
will not send you a single byte unless a separate service — the **Trust
Gateway** — says there is a valid chain of vouches connecting the two of you.
No vouch, no file.

---

## 1. The pieces

There are four moving parts. Only the first one lives in this repository.

| Piece | What it is | Where it lives |
|---|---|---|
| **The agent** | A Python program each user runs. It seeds files, downloads files, and talks to the other two services. | This repo, `agent/` |
| **The trust gateway** | A separate Node/Express service backed by Postgres and Neo4j. It stores who vouched for whom and answers "is there a trust path from A to B?" | Separate project, default `http://localhost:3002` |
| **The tracker** | A small HTTP service that keeps a list of "which agent IDs currently have file X". | Separate project, default `http://localhost:8000` |
| **iroh** | A peer-to-peer transport library. It connects two agents directly by identity, doing NAT hole-punching itself, with a relay as a fallback. | Third-party dependency |

Important distinction: the **tracker only tells you who has a file**. The
**gateway decides whether you are allowed to have it**. Neither one ever
touches the file bytes.

---

## 2. Identity — one key, used for everything

Every agent has a single Ed25519 keypair, stored as a PEM file at
`config/identity.pem` (see `agent/identity.py`).

The **public key, base64-encoded, IS the agent's ID**. There is no username,
no account, no registration form. The same key does three jobs at once:

1. It is the `agent_id` the gateway knows you by.
2. It signs the vouch and revoke payloads the gateway verifies.
3. iroh derives its network address (`EndpointId`) from the same raw private
   key bytes, so the identity you have trust with is literally the identity
   you connect as. Nobody can pretend to be you on the network without
   holding your key.

That third point is why `AgentIdentity` has the one deliberate hole in its
otherwise sealed design: `raw_private_bytes()`. Every other part of the
program only ever sees `agent_id`, `sign()`, and `verify()`. That single
method exists purely to hand the key to iroh's `EndpointOptions`, so iroh
doesn't invent a second, unrelated identity the gateway has never heard of.

The key file is written unencrypted with `chmod 600`. That is a known
shortcut for a demo project; production would put a passphrase on it.

---

## 3. Trust — how permission actually works

### Vouching

Trust is a directed graph. `A vouches for B` is one signed edge. It has an
issue time and an **expiry time that is mandatory** — trust lapses on its
own; revocation is not the only way it ends.

You vouch for someone by running:

```bash
vouch <their_agent_id>
```

That signs a canonical JSON payload and POSTs it to the gateway. Revoking is
the same shape:

```bash
revoke <their_agent_id>
```

### The signing rule that must not be broken

`agent/gateway_client.py` builds the exact JSON string the gateway's
`authMiddleware.js` will rebuild on its side, and signs that:

- vouch: `{issuer_id, subject_id, issued_at, expires_at}`
- revoke: `{issuer_id, subject_id, action: "REVOKE", timestamp}`

Both are serialized with `separators=(",", ":")` — no spaces — and **in that
exact key order**, because Python preserves dict insertion order and that
order becomes the wire order. If either side reorders a key or adds a space,
every signature fails. Timestamps are in **seconds**; the gateway multiplies
by 1000 itself for Neo4j. Do not pre-multiply.

### Asking "am I allowed?"

`GET /path?start_id=…&end_id=…` on the gateway. It answers with `verified`,
`degrees_of_separation`, and the chain. This is a read, so it needs no
signature.

The agent then applies its own extra rule on top: even if the gateway says a
path exists, the agent rejects it if `degrees_of_separation > max_depth`
(default 3). A friend-of-a-friend-of-a-friend is the limit. You set your own
limit; the gateway does not set it for you.

### Fail closed

If the gateway is unreachable, **every trust check rejects**. There is no
local cache fallback, no "assume yes if we can't ask". The gateway going
down means transfers stop, not that transfers become unrestricted. This is
deliberate and applies identically on both sides of a transfer.

### The local trust engine

`agent/trust.py` contains a complete, standalone chain verifier — it walks a
list of `Vouch` objects, checking each signature, expiry, revocation status,
that each edge's subject is the next edge's issuer, and that the last edge
lands on the claimed subject.

**Be aware:** in the current running system, this is not what gates
transfers. `p2p_server.py` and `downloader.py` both call
`gateway.check_path()` instead. The only thing they read off the
`TrustEngine` is `max_depth`. `verify_chain()` is the offline/local
implementation of the same idea — the gateway is the authoritative one.

---

## 4. Files are named by their hash

A file's identity is its **SHA-256 hash**. That is its name on disk, its ID
on the tracker, and what you send a friend so they can ask for it.

This means:

- You cannot ask for a file by name, only by hash.
- The receiver verifies the finished file's hash against what they asked
  for. If a peer sends different content, the hash won't match and the file
  is deleted. There is nothing to trust about the peer's honesty here — the
  hash checks itself.
- Two identical files are the same file, automatically.

The real filename is kept separately in a small sidecar JSON file,
`<hash>.meta`, containing `{"file_name": "..."}`. It's cosmetic — it exists
so the receiver can save the download as `song.mp3` instead of a 64-character
hash. It is never trusted for anything security-related; the receiver runs
`os.path.basename()` on it before using it, so a malicious name like
`../../etc/passwd` can't escape the output directory.

---

## 5. The files in this repo

### `agent/` — the agent itself

**`identity.py`**
The Ed25519 keypair. Loads from PEM or generates and saves one on first run.
Provides `agent_id`, `sign()`, and a static `verify()`. `verify()` returns
`False` on any failure rather than raising, so callers don't need a
try/except at every call site.

**`config.py`**
Pydantic settings loaded from `config/settings.yaml`, with defaults for
everything missing, then overridden by environment variables
(`P2P_GATEWAY_URL`, `P2P_TRACKER_URL`, `P2P_SERVER_PORT`,
`P2P_STORAGE_ROOT`, `P2P_TRUST_MAX_DEPTH`, `P2P_IDENTITY_PATH`, and a few
more). The env layer exists so a container can be configured without
mounting a config file.

Note: `server.host` in the config is **not** used to bind anything.
`main.py` hardcodes the control API to `127.0.0.1`. The field is kept for
backward compatibility only.

**`messages.py`**
Every message that can cross the wire, as a Pydantic model:
`HandshakeRequest`/`Response`, `Vouch`, `Revoke`, `FileInfoRequest`/
`Response`, `FileRequest`, `FileRequestAck`, `FileRequestReject`,
`ChunkHeader`, `TransferComplete`, `ErrorMessage`.

The key design decision here: `FileRequest` asks for a **byte range**, not a
whole file. Everything about multi-peer downloading depends on that
granularity.

**`serializer.py`**
Turns models into JSON bytes and back. Decoding reads the `type` field
first and looks up the matching model in a plain dictionary — manual
dispatch, not a Pydantic discriminated union, because these models aren't
nested inside a common envelope. Every failure mode (bad JSON, unknown type,
schema mismatch) surfaces as one exception, `DeserializationError`, so
callers never need to know Pydantic is involved.

`decode_as()` additionally enforces the message type the caller expected,
for points in the protocol where the next message is predictable.

**`trust.py`**
Issues and verifies vouches and revokes locally. See the caveat in section 3
about it not being the live gate.

**`gateway_client.py`**
Async HTTP client for the gateway: `register()`, `vouch_for()`, `revoke()`,
`check_path()`. `register()` treats HTTP 409 (already registered) as
success, because `main.py` calls it on every startup.

**`tracker_client.py`**
Async HTTP client for the tracker: `register(file_hashes)`,
`get_peers(file_hash)`, `keepalive()`, `unregister()`. Retries transport
failures twice with a backoff; HTTP error statuses are not retried.

Since the move to iroh, `PeerAddress` carries **only an agent_id** — no host,
no port. The tracker's whole job shrank to "who has this file". Actually
reaching that peer is iroh's problem.

`get_peers()` filters you out of your own results.

**`storage.py`**
`StorageBackend` is an abstract interface; `LocalStorage` is the disk
implementation. All methods are async, and disk I/O runs through
`asyncio.to_thread` so it never blocks the event loop.

The four methods that matter for transfers:

- `read_range(hash, start, end)` — streams a byte range in 64 KB pieces,
  never buffering the whole range.
- `preallocate(hash, size)` — creates a sparse file of exactly the right
  size before any download starts.
- `write_chunk_at(hash, offset, data)` — seeks and writes at an offset.
- `list_files()` — what to announce to the tracker.

`preallocate` + `write_chunk_at` are what allow several peers to write
different parts of the same file at the same time without coordinating.
Each writer opens its own handle, seeks to its own offset, writes, closes.
No locking needed because no two writers target the same bytes.

**`p2p_server.py` — the seeding side**
Binds an iroh `Endpoint` using this agent's existing private key and accepts
incoming connections forever.

Routing works like this: connections are accepted, streams are accepted on
each connection, and the first message on a stream is decoded — its `type`
field decides what happens. That replaces what used to be URL paths in an
older HTTP version of this project.

Three request types are handled, and **all three run the same trust check
first**:

- `HandshakeRequest` → check trust, then sign the caller's nonce and return
  it. Signing the nonce proves you hold the private key for your claimed
  agent_id.
- `FileInfoRequest` → check trust, then return size and filename. This is
  gated on purpose: file size and name are not public just because someone
  knows the hash, and letting anyone probe hashes for metadata is a real
  leak even without handing over bytes.
- `FileRequest` → check trust, then serve the byte range.

The trust check in all three is: ask the gateway for a path from me to the
sender; reject if unreachable, reject if unverified, reject if it exceeds
`max_depth`.

There is a development escape hatch, `P2P_TRUST_ALL=true`, which bypasses
every trust check. It logs a loud warning on startup. It must never be set
outside local development.

Two size constants matter:

- `SUB_CHUNK_SIZE = 8 MB` — the size of one request/response round trip.
- `MAX_READ_BYTES = 64 MB` — a defensive ceiling on how much will be read
  from a single stream, so a misbehaving peer can't make you allocate
  unbounded memory.

**`downloader.py` — the fetching side**
Does the work of getting a file:

1. Ask the tracker for peers that have the hash.
2. Handshake with all of them at once; keep the ones that pass.
3. Ask the first trusted peer for the file size (`FileInfoRequest`).
4. Preallocate the destination file at that exact size.
5. Split the size into one contiguous range per peer (`_split_ranges`,
   minimum 256 KB per peer — no point splitting a small file across four
   connections).
6. Fetch all ranges in parallel, each range as a sequence of 8 MB
   sub-chunks, each sub-chunk verified and written to disk immediately.
7. When all ranges finish, re-read the whole assembled file and check its
   SHA-256 against the hash that was requested.

The handshake in step 2 does four separate checks, and all four must pass:
the response must decode as a `HandshakeResponse`, the nonce signature must
verify, the responder's `sender_id` must equal the peer you actually dialed
(no bait-and-switch), and the gateway must confirm a path within `max_depth`.

**Failure handling.** A single peer failing does not kill the download
immediately — `asyncio.gather(..., return_exceptions=True)` collects
results, failures are logged, and the surviving chunks are checked for gaps.
If there is a gap, or the total is short, the partial file is **deleted** and
the download raises. If the final hash doesn't match, the file is deleted
too. You never end up with a silently corrupt or half-written file.

**Automatic punishment.** If a peer's delivered bytes don't match the
checksum that peer itself declared in its own `ChunkHeader`, that raises
`ChecksumMismatchError`, which is treated differently from ordinary network
trouble. QUIC already guarantees the bytes arrived intact, so a mismatch
means the peer's own code sent bytes inconsistent with its own claim. The
downloader counts these per peer and, at the threshold (default: **one**),
calls `gateway.revoke()` on that peer. Bad behaviour costs you your place in
the trust graph, automatically.

**`control_api.py` — the local remote control**
A small FastAPI app so an outside process can tell an *already-running*
agent to download something, using that agent's endpoint, identity, and
trust relationships.

- `POST /downloads {file_hash}` → starts a background task, returns an ID
  immediately.
- `GET /downloads/{id}` → status, bytes so far, total expected, and on
  completion the absolute path on disk.
- `GET /downloads` → list.
- `GET /health`.

Downloads are polled by ID rather than blocking the POST, because a large
file takes longer than any sane HTTP client timeout.

**This API has no authentication at all, on purpose.** The only protection
is that it is bound to `127.0.0.1`. Anyone who can reach this port can make
your agent download files under your identity, spending your trust
relationships. `main.py` hardcodes the bind address and ignores the config
value specifically so this cannot be misconfigured into being exposed.

The completion response returns an **absolute** storage path, because the
CLI reading it is a different process that may have been started from a
different directory.

**`main.py` — startup and wiring**
In order:

1. Load config, load or create the identity.
2. Build the trust engine.
3. Register with the gateway (a failure here is logged, not fatal).
4. Pick a storage backend.
5. Build the tracker client.
6. Build and start the `P2PServer` — this binds the iroh endpoint.
7. Announce every file already in storage to the tracker.
8. Build the `Downloader`, **reusing the server's endpoint** — one endpoint
   for both directions, since two endpoints under one key would be an
   identity collision on the network.
9. Start the control API on `127.0.0.1` via uvicorn.
10. Loop, re-announcing to the tracker every 120 seconds, until SIGINT or
    SIGTERM.

On shutdown: stop the control API, close the endpoint, unregister from the
tracker, close both HTTP clients.

### `devtools/` — the command line tools

Installed as console scripts by `pyproject.toml`:

| Command | File | What it does |
|---|---|---|
| `upload --file X` | `ingest_file.py` | Hashes a file, copies it into storage under its hash, writes the `.meta` sidecar, prints the hash to share. |
| `receive <hash>` | `receive.py` | Talks to your running agent's control API, starts a download, prints a live progress bar, and copies the result out under its real filename. |
| `vouch <id>` | `vouch_cli.py` | Grants trust to another agent. |
| `revoke <id>` | `revoke_cli.py` | Withdraws it. |
| `register` | `register_cli.py` | Registers your identity with the gateway and prints your agent ID. |

Not installed as commands, run with `python -m`:

- `print_identity.py` — prints the agent ID for a given PEM file.
- `download_file.py` — a full download run in its own process, with its own
  throwaway endpoint. Can either discover peers through the tracker or take
  a peer's agent ID directly with `--peer-agent-id`, which is how you test
  without a tracker running.
- `test_handshake.py` — does exactly one handshake against one peer and
  prints ACCEPTED or REJECTED. The fastest way to prove the trust path works.
  Also the way to prove a revoke takes effect immediately: vouch → handshake
  (accepted) → revoke → handshake (rejected, on the very next call).

**Both `download_file.py` and `test_handshake.py` bind their own iroh
endpoint using your identity. Stop your own `agent.main` process before
running them.** Two endpoints under the same secret key at the same time is
a genuine network identity collision, not just a Python-level conflict.

### Other files

- **`upload.ps1`** — a Windows-only alternative to `upload`. Opens a file
  picker dialog, hashes the chosen file, copies it into `downloads_a/` under
  its hash, and writes the `.meta` sidecar. Same result as `upload`, more
  convenient on Windows.
- **`Caddyfile`** — a reverse proxy for exposing the two backing services
  through one port during testing. Port 4000: `/tracker/*` goes to the
  tracker on 8000, everything else to the gateway on 3000.
- **`ngrok.exe`** — used to expose those services to the internet when
  testing between two machines that aren't on the same network.
- **`config/identity.pem`** — your private key. Gitignored. Deleting it
  means losing your identity and every vouch anyone made to it.
- **`downloads/`, `downloads_a/`** — storage roots. Files named by hash,
  plus `.meta` sidecars.

---

## 6. The full workflow

### Setting up

Both people run:

```bash
register
```

This creates `config/identity.pem` if it doesn't exist, registers with the
gateway, and prints the agent ID. They exchange those IDs out of band —
chat, email, whatever.

Then each vouches for the other:

```bash
vouch <their_agent_id>
```

One-way vouching is not enough. The sender checks the receiver, and the
receiver checks the sender, independently. Both directions must resolve.

### Sharing a file

The sender runs:

```bash
upload --file "song.mp3"
```

The file is hashed, copied into the storage root under that hash, and a
`.meta` sidecar records the real name. The command prints the hash. The
sender sends that hash to the receiver.

Both people then run their agent:

```bash
python -m agent.main
```

The sender's agent announces every file in its storage to the tracker, and
re-announces every two minutes so the tracker knows it's still alive.

### Downloading

The receiver runs:

```bash
receive <hash>
```

That posts to their own agent's control API on `127.0.0.1:9000`, then polls
for progress. Behind that one command:

1. **Discover** — the receiver's agent asks the tracker who has this hash.
   Gets back a list of agent IDs.
2. **Handshake** — dials every candidate over iroh in parallel. For each:
   sends a random nonce; the peer checks the gateway for a path back to the
   receiver and refuses outright if there isn't one; if it passes, the peer
   signs the nonce and returns it; the receiver verifies that signature,
   confirms the responder is who was dialed, and then independently asks the
   gateway for a path in its own direction. Both sides check. Neither trusts
   the other's answer.
3. **Size** — a `FileInfoRequest` to the first trusted peer, which is itself
   trust-gated on the peer's side.
4. **Preallocate** — a sparse file of exactly that size is created locally.
5. **Split** — the byte range is divided evenly among the trusted peers.
6. **Fetch** — every peer is asked for its range at once. Each range is
   pulled in 8 MB sub-chunks. For each sub-chunk the peer replies with an
   Ack, then a header containing a SHA-256 of exactly those bytes, then the
   raw bytes, then a completion frame. The receiver hashes the bytes it got
   and compares. Match → write to the correct offset and drop it from
   memory. Mismatch → error, and that peer gets revoked.
7. **Verify** — the assembled file is re-read end to end and its SHA-256
   compared to the requested hash. Mismatch → deleted.
8. **Export** — the file is copied out of the hash-named storage into the
   current directory under its real name from the `.meta` sidecar.

Only after step 7 passes does the receiver have a file.

### Removing access

```bash
revoke <their_agent_id>
```

The next trust check fails. There is no cached "yes" anywhere on the agent
side to expire first — every check is a live query to the gateway, so this
takes effect on the very next request.

---

## 7. Why the design is the way it is

**Why hashes instead of filenames?** Because the receiver can verify a hash
without trusting anyone. A filename proves nothing.

**Why check trust on both sides?** Because a one-sided check only protects
one party. The seeder checks before serving; the downloader checks before
accepting. A malicious peer can lie about its own answer, so neither side
uses the other's.

**Why 8 MB sub-chunks?** Memory. Without them, a 2 GB transfer would mean
holding 2 GB in RAM on each side. With them, a 2 GB file becomes roughly 250
independent 8 MB round trips and neither side ever holds more than 8 MB.
Each sub-chunk is also verified on its own, so corruption is caught early
rather than after the whole file has arrived.

**Why one contiguous range per peer instead of interleaving?** Because gap
detection becomes trivial — sort the completed chunks by start offset and
check they join up. And because sequential reads are kind to disks.

**Why does the tracker not know host and port?** Because iroh doesn't need
them. It resolves an identity to a route itself, punching through NAT where
it can and relaying where it can't. Removing addresses from the tracker also
removes a whole category of stale-data problems — an agent ID stays correct
no matter which network it moves to.

**Why fail closed when the gateway is down?** Because the alternative is
that knocking the gateway offline turns the whole network into an open one.
A denial of service is a much smaller problem than an unrestricted network.

**Why revoke on a single checksum mismatch?** Because QUIC already guarantees
the bytes weren't corrupted in transit. A peer whose bytes disagree with its
own declared checksum isn't unlucky, it's broken or hostile. Neither is worth
staying vouched for, and the vouch can always be reissued.

**Why is the control API unauthenticated?** Because adding a password would
imply it is safe to expose, and it is not. The security boundary is the
loopback interface, and the bind address is hardcoded so that boundary can't
be moved by editing a config file.

---

## 8. Known gaps

These are real and worth knowing before extending anything.

- **`config/settings.yaml` doesn't exist in the repo.** Everything runs on
  the defaults in `config.py` plus environment variables. If you want a
  settings file, create it — `load_config()` already handles it being absent.
- **`agent/http_storage_adapter.py` doesn't exist.** `main.py` imports it
  when `storage.use_http` is true. Turning that flag on will crash at
  startup with an `ImportError`. Local disk is the only working backend.
- **The default gateway URL disagrees with the tooling.** `config.py`
  defaults to port 3002, the `Caddyfile` proxies to 3000, and
  `test_handshake.py` defaults to 3000. Set `P2P_GATEWAY_URL` explicitly
  rather than relying on a default.
- **The seeder buffers a full sub-chunk in memory** to compute the checksum
  before sending. Bounded at 8 MB, so it's fine, but it isn't true streaming.
- **`_run_test_handshake` in `main.py` is stale.** It calls `_fetch_chunk`
  with the old signature and reads `chunk.data`, which `ChunkResult` no
  longer has. It only runs when `P2P_TEST_HANDSHAKE_PEER` is set. Use
  `devtools/test_handshake.py` instead.
- **`tests/` is empty.**
- **`TrustEngine.verify_chain()` is dead code in the live path.** Fully
  implemented and correct, but the gateway does the actual gating. Keep it
  in sync or delete it deliberately — don't leave it half-maintained.
- **The private key is stored unencrypted.** Fine for a demo, not for
  production.
- **A peer that fails mid-range takes the whole download down.** There is no
  reassignment of a failed peer's range to a surviving peer; the gap check
  fails and the partial file is deleted. Correct, but not resilient.
