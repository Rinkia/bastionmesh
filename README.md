# bastionmesh

**A runtime security gateway between A2A agents.** One process fronts every peer agent in a
deployment, so it sees each agent-to-agent hop and can act on it:

- **Peer injection:** scans what a peer sends back (task artifacts, status messages, history,
  streamed chunks) for prompt injection before the calling agent reads it.
- **Relay / worm:** notices when an agent passes an injected payload on to another peer.
- **Card rug-pulls and bypass:** fetches, scans (bastionsupply) and pins each peer's agent card,
  then rewrites it so callers only ever see the mesh's endpoint.
- **Runaway delegation:** caps delegation depth, blocks A → B → A cycles, and limits how fast and
  how wide any one agent fans out. No cooperation from the agents is needed.
- **Unauthorized use:** per-caller keys, per-caller peer allow lists, per-peer method allow lists,
  and an allow list for push-notification webhooks (an exfiltration and SSRF path).

OWASP Agentic Top 10: ASI07 insecure inter-agent communication, ASI08 cascading failures,
ASI10 rogue agents. Part of the [bastion](https://bastiondefense.dev) suite; the A2A sibling of
[bastiongate](https://github.com/Rinkia/bastiongate) (MCP).

```bash
pip install bastionmesh
bastionmesh demo      # offline replay: a peer injects, the host relays it, the mesh flags both
```

## Quickstart

```bash
export MESH_KEY_ORCHESTRATOR=$(python -c "import secrets; print(secrets.token_urlsafe(24))")
bastionmesh check --policy mesh.yaml --lock   # scan every peer card, pin the `card: lock` ones
bastionmesh run --policy mesh.yaml --log mesh.jsonl
```

Point each agent at the mesh instead of the peer:

| Before | After |
|---|---|
| `https://researcher.example/.well-known/agent-card.json` | `http://127.0.0.1:9100/peers/researcher/.well-known/agent-card.json` |
| `https://researcher.example/a2a` | `http://127.0.0.1:9100/peers/researcher/` + header `X-Bastionmesh-Key` |

A2A clients that discover peers by card need no other change: the rewritten card already points
at the mesh. A full policy is in [examples/mesh.example.yaml](examples/mesh.example.yaml).

## What it checks, in order

```
request   caller key -> caller may call peer -> method allowed -> card ok (pin/lock, findings)
          -> rate + in-flight caps -> delegation depth + cycle -> push webhook allowed
          -> hidden unicode + known payloads -> relay of flagged text -> credentials (redact)
response  every text part (message, task status, artifacts, history, stream events)
          -> full injection signatures; streamed chunks are scanned with the previous 256 chars
```

Scanning is split by direction on purpose. A delegation *is* an instruction ("always include
sources"), so requests only get hidden-unicode and known-payload checks. A reply should be data,
so replies get the full signature set, the same one bastiongate runs on MCP tool results.

A block is a JSON-RPC error with code `-32000` (A2A owns -32001..-32099) and a reason in
`error.data.bastionmesh`: `caller-denied`, `method-denied`, `card-drift`, `card-unverified`,
`card-findings`, `rate-limited`, `depth-exceeded`, `push-webhook-denied`, `injection`, `relay`,
`secret`, `oversize` (more message text than `limits.max_message_chars`, default 1M: refused,
never truncated), `malformed` (a key spelled so a lenient decoder would read what the mesh cannot, or nesting too deep to scan: always refused). In a stream, the blocked event is replaced by the error and the stream is closed.

## Warn first, then block

Rules you write (caller and method allow lists, webhooks, caps, cycles, card drift) always
enforce. Heuristic detectors (`on_injection`, `on_relay`, `on_card_findings`) ship in **warn**:
the message is forwarded, a `WARN` line goes to stderr and a `warned` event to the log. Run in
warn, read the log, then switch to `block`.

## Delegation depth without cooperation

While a request *into* peer P is in flight (a blocking send or an open stream), P's own outbound
requests continue that chain, so the mesh knows `orchestrator -> researcher -> mailer` is depth 2
without any header or agent change. This needs callers and peers to share names
(`callers.researcher` is the same agent as `peers.researcher`).

## Logs and forensics

`--log mesh.jsonl` records ids, peers, callers, reasons and counts, never message content.
`--trace-content trace.jsonl` additionally writes a **bastiontrace v3** trace (every delegation
and reply as an `agent_message`, with provenance edges), so
`bastiontrace analyze trace.jsonl` reconstructs a cascade after the fact. It contains message
content: treat it as sensitive. Metrics: `GET /__bastionmesh/metrics` (same key as calls).

## bastionmesh and agentgateway

[agentgateway](https://agentgateway.dev) (Linux Foundation) already routes A2A and MCP traffic
with authentication, authorization and rate limits. bastionmesh overlaps on routing and caller
keys, but its job is content: injection in replies, relays between agents, card pinning with
bastionsupply's checks, and bastiontrace-ready logs. They compose. Keep agentgateway at the edge
and run the mesh behind it on loopback in open mode:

```yaml
# mesh.yaml behind agentgateway: agentgateway authenticates, the mesh inspects
listen: 127.0.0.1:9100
peers:
  researcher: {url: https://researcher.example/a2a}
# no callers: open mode, allowed only on loopback; agentgateway's A2A route targets
# http://127.0.0.1:9100/peers/researcher/
```

In open mode the mesh identifies callers by IP, so per-caller caps apply to the gateway as a
whole and delegation depth cannot be attributed. Use caller keys when that matters.

## Limits (read these)

- **Async delegation is not depth-capped.** Send-then-poll ends the inbound request, so the chain
  breaks. Cycles and depth are enforced for blocking sends and streams (TODOS.md).
- **Relay detection is literal.** A paraphrased payload is not matched; a copied one (32
  characters or more, or the matched injection phrase) is. Shingles cover the first and last
  256 KB of each part; the injection scan itself reads every character.
- **Streamed payloads longer than 256 characters split across chunks** can evade the chunk carry,
  as can a split with more than 4096 other artifacts interleaved between the halves.
- **Credentials only.** Outbound redaction targets keys and tokens, not emails or phone numbers
  (delegations carry those routinely). A part that holds a credential is redacted as a whole
  PII pass, so an email next to a key is redacted too.
- **Encoded text** (base64, hex, binary, base32, ascii85/base85, Morse, escapes) is decoded
  and scanned. rot13, leetspeak and reversed text are not, in replies or requests. Made-up
  ciphers are never decodable.
- **Binary parts** (`raw`, file bytes) are counted in the log, not scanned.
- **JSON-RPC binding only.** REST and gRPC interfaces are removed from rewritten cards so callers
  cannot route around the mesh; JWS card signatures are dropped for the same reason (the mesh is
  the trust anchor), and are not verified.
- **Card refresh** happens every 5 minutes. When a peer's card endpoint is down the last verified
  card stands; a `card: lock` peer that was never verified since start is refused.
- **Streams are capped at 10 MB in total** (and 1 MB per line); a longer stream is cut. There is
  no total stream deadline (long tasks stream for a long time): a peer that trickles bytes keeps
  its caller's in-flight slot until the 120 s idle timeout.
- **Rewritten cards keep the peer's other URLs** (documentation, icon, OAuth endpoints): only
  the A2A interfaces are rewritten.
- **Auth throttling is per IP.** Agents sharing one IP share the 10-failures-per-minute budget.
- **No global connection cap** yet: keep the listen address on loopback or behind a proxy.

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q     # includes interop tests against the official a2a-sdk server and client
```

MIT licensed.
