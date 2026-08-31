# p2p-agent

A peer-to-peer file sharing agent where you can only download from people who
have vouched for you.

Files move directly between machines. No server stores them. But before any
bytes move, both sides ask a **trust gateway** whether a chain of vouches
connects them. No vouch, no file.

---

## How it works

Four parts:

- **The agent** (this repo) — you run it, it seeds and downloads files.
- **Trust gateway** — separate Node/Postgres/Neo4j service. Stores who
  vouched for whom, answers "is there a path from A to B?"
- **Tracker** — small HTTP service. Only knows which agents have which file.
- **iroh** — connects two agents directly by identity. Handles NAT
  hole-punching itself, falls back to a relay.

The tracker tells you *who has a file*. The gateway decides *if you're
allowed to have it*. Neither ever touches the file itself.

Your identity is a single Ed25519 key. The public key **is** your agent ID —
no accounts, no usernames. The same key signs your vouches and is what iroh
uses as your network address, so you can't be impersonated.

Files are named by their SHA-256 hash. You share a file by sending someone
the hash. They verify what they receive against it, so a peer can't quietly
send you something else.

---

## Install

```bash
pip install -e .
```

Needs Python 3.10+. You also need a trust gateway and a tracker running
(separate projects).

---

## Setup

Both people do this once.

**1. Create your identity and register:**

```bash
register
```

Prints your agent ID. Send it to the other person however you like — chat,
email, anything.

**2. Vouch for each other:**

```bash
vouch <their_agent_id>
```

Both people must run this. One-way vouching isn't enough — each side checks
trust independently before sending or accepting anything.

---

## Sharing a file

```bash
upload --file "song.mp3"
```

Hashes the file, copies it into your storage folder, prints the hash. Send
that hash to whoever should get the file.

On Windows you can use `.\upload.ps1` instead, which opens a file picker.

Then start your agent and leave it running:

```bash
python -m agent.main
```

---

## Downloading a file

With your own agent running, in another terminal:

```bash
receive <hash>
```

Shows a progress bar and saves the file under its real name when done.

What happens behind that one command:

1. Ask the tracker who has this hash.
2. Handshake with each of them. Both sides check the gateway for a trust
   path. Both must pass.
3. Ask a trusted peer for the file size.
4. Split the file into ranges, one per peer, and fetch them all at once in
   8 MB pieces.
5. Verify each piece against the checksum the peer declared, then verify the
   whole finished file against the hash you asked for.

If verification fails at any point, the partial file is deleted. You never
end up with something corrupt.

If a peer sends bytes that don't match its own declared checksum, your agent
automatically revokes its vouch for that peer.

---

## Removing access

```bash
revoke <their_agent_id>
```

Takes effect on the very next request. Nothing is cached on the agent side —
every trust check is a live query to the gateway.

---

## Commands

| Command | What it does |
|---|---|
| `register` | Create identity, register with the gateway, print your agent ID |
| `vouch <id>` | Grant trust to another agent |
| `revoke <id>` | Withdraw it |
| `upload --file X` | Add a file to your storage and get its hash |
| `receive <hash>` | Download a file |
| `python -m agent.main` | Run the agent (needed for both seeding and downloading) |

---

## Configuration

Reads `config/settings.yaml` if present, otherwise uses defaults. Environment
variables override both:

```
P2P_GATEWAY_URL      trust gateway address
P2P_TRACKER_URL      tracker address
P2P_STORAGE_ROOT     where files are kept
P2P_SERVER_PORT      local control API port (default 9000)
P2P_TRUST_MAX_DEPTH  how many hops of trust to accept (default 3)
P2P_IDENTITY_PATH    path to your key file
```

`max_depth` is yours to set. At the default of 3, a friend-of-a-friend-of-a-
friend is as far as trust reaches.

---

## Layout

```
agent/
  identity.py        Ed25519 keypair — your agent ID
  trust.py           vouch chain verification
  gateway_client.py  talks to the trust gateway
  tracker_client.py  talks to the tracker
  p2p_server.py      seeding side — serves files to trusted peers
  downloader.py      fetching side — multi-peer parallel download
  storage.py         disk backend, ranged reads and offset writes
  control_api.py     local-only HTTP API (127.0.0.1)
  messages.py        wire protocol
  serializer.py      encode/decode
  main.py            startup and wiring
devtools/            CLI tools
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full picture.

---

## Security notes

- **If the gateway is unreachable, everything is rejected.** No fallback, no
  cached answers. The gateway going down stops transfers rather than opening
  the network up.
- **The control API has no auth and is bound to `127.0.0.1` only.** Anyone
  who can reach that port can make your agent download things under your
  identity. The bind address is hardcoded so it can't be exposed by editing
  config.
- **`P2P_TRUST_ALL=true` disables all trust checks.** Local development only.
- **Your key file is stored unencrypted.** Fine for a demo, not for
  production.

---

## Current limitations

- `config/settings.yaml` isn't in the repo — defaults and env vars only.
- The HTTP storage backend (`storage.use_http`) is referenced but not
  implemented; local disk is the only working backend.
- If a peer drops mid-transfer, its range isn't reassigned to another peer —
  the download fails and the partial file is deleted.
- No tests yet.
