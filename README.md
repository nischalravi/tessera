# Tessera

Access-as-code for cloud and data infrastructure.

Tessera builds a live graph of who can actually do what across your identity provider, cloud, SaaS and data platforms. That includes people, service accounts, API keys and AI agents. Access rules live as Cedar policies in Git, every change is simulated for blast radius before merge, and access nobody uses is removed safely and reversibly.

> Working name. Early-stage and private.

## Repository layout

| Path | What it is |
|---|---|
| [`mvp/`](mvp/) | Runnable MVP: FastAPI + SQLite backend, React + Vite UI, demo connectors for Workday, Okta, AWS, GitHub and Snowflake |
| [`docs/product-architecture-spec.md`](docs/product-architecture-spec.md) | Product and architecture spec: positioning, data model, production architecture, roadmap, pricing, risks |
| [`docs/competitive-analysis.md`](docs/competitive-analysis.md) | Market map and competitor analysis (SailPoint, Saviynt, Okta, Entra, ConductorOne, Veza, NHI vendors), with sources |
| [`prototype/tessera-prototype.html`](prototype/tessera-prototype.html) | Single-file clickable UI prototype for demos and design-partner conversations |

## Run the MVP

Requirements: Python 3.11+, Node 18+, npm.

```bash
cd mvp
./run.sh          # installs deps, seeds the demo company, starts API :8000 and UI :5173
./run.sh test     # backend test suite
```

Then open http://localhost:5173. The API reference is at http://127.0.0.1:8000/docs.

All demo data is fictional and runs locally. No cloud credentials are needed.

## Status

The MVP demonstrates the core ideas against seeded data. It is not production software yet:

- No authentication on the API or UI
- Revokes and lifecycle plans update Tessera's graph only; nothing is written back to source systems
- Connectors are demo generators; no scheduled sync against real systems
- AWS IAM conditions, explicit denies and wildcards are not evaluated

See the MVP phase in the spec's roadmap for what comes next.
