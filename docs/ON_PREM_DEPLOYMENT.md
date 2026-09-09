# SecureMailScope offline/on-prem deployment

## Prerequisites

- A dedicated Linux or Windows host with Docker Engine/Desktop and Compose v2
- At least 4 CPU cores, 8 GB RAM, and 20 GB free disk space
- Only ports 3000, 3001, 8000, and 9090 exposed to the trusted management network
- An HTTPS reverse proxy for access beyond the local machine

## First installation

```powershell
git clone <your-securemailscope-repository-url>
cd SIH_2026_Team_Unfazed
Copy-Item .env.example .env
python tools\init_secrets.py
docker compose pull
docker compose up -d --build
docker compose ps
```

The generator writes random values under the Git-ignored `secrets/` directory
and never prints them. Transfer that directory only through an approved secret
channel. Never commit it or include it in ordinary support bundles.

## Offline image transfer

On an internet-connected staging host:

```powershell
docker compose build
docker compose pull
docker save -o securemailscope-images.tar `
  sih_2026_team_unfazed-api sih_2026_team_unfazed-worker `
  sih_2026_team_unfazed-frontend sih_2026_team_unfazed-zeek `
  postgres:17-alpine redis:7-alpine prom/prometheus:v3.5.0 grafana/grafana:12.1.1
```

Transfer the repository, archive, and separately protected secrets to the
isolated host. Run `docker load -i securemailscope-images.tar`, followed by
`docker compose up -d --no-build`.

## Configuration and validation

Non-secret settings live in `.env`. Secrets are mounted read-only from
`secrets/*.txt` under `/run/secrets`; they are not placed in container
environment variables. Production startup rejects missing, short, or
placeholder JWT and Zeek secrets.

```powershell
docker compose config --quiet
docker compose up -d --build
Invoke-RestMethod http://127.0.0.1:8000/api/health/ready
```

Set `SECUREMAILSCOPE_ALLOWED_ORIGINS` to the exact HTTPS frontend origin. Never
use `*` in production.

## Secret rotation

Run rotation while the existing stack is healthy:

```powershell
python tools\init_secrets.py
docker compose up -d --force-recreate postgres zeek api worker grafana
```

PostgreSQL and Grafana credentials are rotated before files are atomically
replaced. JWT rotation signs out existing sessions by design.

## Operations

- Readiness: `http://localhost:8000/api/health/ready`
- Metrics: `http://localhost:8000/metrics`
- Grafana: `http://localhost:3001`
- Backup: `.\tools\backup.ps1`
- Logs: `docker compose logs -f api worker zeek`
- Upgrade: take a backup, load/pull images, then run `docker compose up -d`

Keep Docker volumes and `backups/` on encrypted storage. Test restoration in a
separate environment before every production upgrade.
