"""bastionmesh: a runtime security gateway between A2A agents.

One process fronts every peer agent in a deployment, so it sees each
agent-to-agent hop: it scans peer replies for prompt injection, catches an
agent relaying an injected payload to another peer, pins and rewrites agent
cards, and caps delegation depth, cycles and fan-out.

The inter-agent leg of the bastion family: scan (bastionsupply), prevent
(agentbastion), attack (bastionprobe), investigate (bastiontrace), gate MCP
(bastiongate), **gate A2A (bastionmesh)**.
"""

from __future__ import annotations

__version__ = "0.2.0"
