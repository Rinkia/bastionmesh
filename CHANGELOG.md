# Changelog

## 0.2.0 (unreleased)

- **Encoded payloads.** Text is decoded with bastioncorpus's `variants`: base64, base32, hex,
  binary, ascii85/base85, Morse, percent and `\u` escapes, including line-wrapped and chained
  forms.
  - **Replies:** the decoded views get the full signature set, through bastionsupply's
    `encoded-injection` check.
  - **Requests:** the decoded views get the known-payload (bastioncorpus) check only, since
    delegations are instructions by design.
  - **Relays:** fingerprints cover decoded text too, so an agent that forwards the decoded
    payload is caught.
  - **Agent cards:** findings include `encoded-injection`.
  - All of it acts under the existing `on_injection` / `on_relay` settings, which default to
    warn.
- Streamed replies: a base64 payload split across chunks is caught by the existing chunk
  carry.
- **Dependency pins:** `bastionsupply>=0.11,<0.12` (bump in the same window as every supply
  minor), `bastiongateway>=0.10`, `bastioncorpus>=0.5`.
- Cost: about 1.2 ms per 4 KB message, of which decoding is about 0.85 ms.

## 0.1.0 (2026-09-30)

First release: a runtime security gateway between A2A agents (backlog item E2 of the bastion
L5 plan).

- HTTP reverse proxy fronting N peers: `/peers/<peer>/` (JSON-RPC) and
  `/peers/<peer>/.well-known/agent-card.json`. A2A v1.0 and v0.3 method names and part shapes.
- Caller keys (`X-Bastionmesh-Key`, from env vars), caller -> peer allow lists, per-peer method
  allow lists; open mode (no callers) only on loopback. Strict policy loader.
- Response scanning with the bastiongate result scanner across messages, task status, artifacts,
  history and stream events; per-artifact 256-char carry for split stream chunks.
- Request scanning limited to hidden unicode and bastioncorpus payloads (delegations are
  instructions by design), plus relay detection (32-char shingles + matched phrases of flagged
  replies) and credential redaction.
- Delegation depth and cycle detection from in-flight request chains; per-caller rate and
  in-flight caps; push-notification webhook allow list (exact scheme/host/port, path on a
  segment boundary, no userinfo).
- Agent cards: fetched with bastionsupply (bounded, no redirects), scanned at real severity,
  pinned (`pin` in memory, `lock` from a bastionsupply lock file), rewritten to the mesh
  (non-JSON-RPC interfaces and signatures dropped). `bastionmesh check [--lock]`.
- `--log` (event log without message content), `--trace-content` (bastiontrace v3 trace),
  metrics endpoint, `bastionmesh demo`.
- Detectors ship in warn (shadow). Promotion bar for a `block` default: 20+ real multi-agent
  sessions with 0 false blocks, recorded here.
- Security review fixes before release: whole-message and joined-part scanning (no truncation,
  overflow parts merged), lone-CR SSE framing, bounded stream reads, non-canonical key and
  deep-nesting refusal (`malformed`), card route honours caller allow lists, atomic chain
  registration, self-call is a cycle, credentials redacted anywhere in params (push-notification webhook tokens exempt),
  `limits.max_message_chars` (oversize fails closed), casefolded key checks, stream carry
  for status text and up to 4096 interleaved artifacts, unauthenticated bodies never read,
  echoed caller text in task history not re-scanned with the reply signatures.
- Interop tests against the official a2a-sdk 1.2 server and client (send, stream, v0.3 compat).

Next: see TODOS.md.
