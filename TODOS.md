# TODOS

## Open

### Async delegation depth (send-then-poll)

**What:** a bounded task-id -> chain map, so a peer's outbound requests made while one of its tasks is still non-terminal (seen via GetTask / status events) continue that task's delegation chain.

**Why:** v0.1 attributes depth only while an inbound request is in flight (blocking send or open stream). Async delegation breaks the chain, so max_depth and cycle checks miss it.

**Context:** deferred in the v0.1 eng review (D1, `bastionmesh-DESIGN.md`). Start in `mesh.py` `_chain`; record task ids from `Mesh.inspect_response` results; TTL + LRU bounds like `RelayStore`.

**Effort:** M
**Priority:** P2
**Depends on:** v0.1 in-flight tracker.

### Global connection cap

**What:** a `limits.max_connections` semaphore around request handling in `server.py`.

**Why:** ThreadingHTTPServer starts one thread per connection; per-caller caps do not bound unauthenticated floods or many long streams.

**Context:** deferred in the v0.1 eng review (D14). Trigger: the first deployment listening off loopback without a proxy in front.

**Effort:** S
**Priority:** P3
**Depends on:** none.

### Later

- JWS agent-card signature verification (suite item E6, needs a crypto dependency decision).
- agentbastion deep-inspect / LLM judge as an optional response inspector.
- Paraphrase-robust relay detection.
- Promote detectors to `block` by default after the dogfood bar in CHANGELOG.
