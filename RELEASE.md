# Release checklist — bastionmesh

Codifies the by-hand release we did for bastionskill so every tool ships the same way.
Publishing is automatic: pushing a **GitHub Release** tag triggers the OIDC publish workflow.

## Pre-flight

- [ ] Working tree clean, on the default branch, up to date with origin.
- [ ] CI green on the matrix (Python 3.10–3.13).
- [ ] Corpus/format contract tests green (`pytest -q`) — if this tool consumes a shared format (injections.jsonl adapters, policy.yaml, trace schema), its contract test still parses the golden fixture.

## Bump

- [ ] Bump `__version__` in the package `__init__.py` **and** `version` in `pyproject.toml` (keep them equal).
- [ ] Update `CHANGELOG.md` (or the README changelog section) with the new version + date.

## First release only

- [ ] On PyPI, add a *pending* trusted publisher for project `bastionmesh`: repo Rinkia/bastionmesh, workflow `publish.yml`, environment `pypi`. Without it the first publish fails.

## A2A spec drift

- [ ] Re-check `bastionmesh/a2a.py` method names and part shapes against the current A2A spec and the latest a2a-sdk; the interop tests run against the installed a2a-sdk.

## Build & verify locally

```bash
python -m build
twine check dist/*
```

- [ ] `twine check` passes (README renders, metadata valid).

## Publish

- [ ] Tag + create a GitHub Release `v<version>` — the `publish.yml` OIDC workflow builds and uploads to PyPI.
- [ ] Confirm on PyPI: `pip install -U bastionmesh` pulls the new version.

## Propagate version truth (PRP G5)

- [ ] Update `suite.json` in the **bastion-site** repo (or let the build-time `scripts/fetch-github-stats.mjs` re-fetch), so bastiondefense.dev never shows a stale version.
- [ ] `bastionsupply doctor` reports the new version as latest.
