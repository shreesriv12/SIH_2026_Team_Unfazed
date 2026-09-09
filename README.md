# SecureMailScope v0.1

The first blueprint milestone: real PCAP -> TShark packet evidence -> canonical session JSON -> Streamlit analyst view.

Start the TShark API:

```powershell
python -m pip install -r requirements.txt
python -m uvicorn api:app --reload
```

Then start the Next.js frontend in another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`.

TShark is found from PATH or `C:\Program Files\Wireshark\tshark.exe`.

## Full Docker deployment

The production-shaped local stack includes Next.js, FastAPI, the analysis worker,
PostgreSQL, Redis, and TShark. Create the environment file once and replace both
placeholder secrets before sharing or deploying the stack:

```powershell
Copy-Item .env.example .env
python tools\init_secrets.py
docker compose up --build -d
docker compose ps
```

Open `http://localhost:3000`. Follow API and worker activity with:

```powershell
docker compose logs -f api worker
```

For the TLS gateway, open `https://localhost` (local development uses Caddy's
internal CA). Set `SECUREMAILSCOPE_DOMAIN` to a real DNS name on a public host;
Caddy then obtains and renews its public certificate automatically. Direct ports
3000 and 8000 are retained for local debugging and should be firewalled in a
public deployment.

Database upgrades run through the one-shot `migrate` service before the API,
worker, or retention service starts. Check the installed revision with
`docker compose exec postgres psql -U securemailscope -d securemailscope -c "SELECT * FROM alembic_version;"`.

Interactive API documentation is available at `http://localhost:8000/docs`
(ReDoc: `http://localhost:8000/redoc`, OpenAPI JSON: `/openapi.json`). New
integrations should use `/api/v1/...`. Existing `/api/...` endpoints remain
available for compatibility and return deprecation/successor-version headers.

Stop the stack without deleting stored analyses:

```powershell
docker compose down
```

Do not add `-v` unless you intentionally want to delete the PostgreSQL, Redis,
and capture volumes.

Secrets are generated in the Git-ignored `secrets/` directory and mounted with
Docker Secrets. See [the on-prem deployment guide](docs/ON_PREM_DEPLOYMENT.md)
for offline installation, configuration validation, and secret rotation.

## Continuous integration and releases

Every push and pull request runs the Python test suite, builds the Next.js
frontend, validates Docker Compose, and builds all application containers.
Pushing a tag such as `v1.0.0` publishes versioned API, worker, Zeek, and
frontend images to GitHub Container Registry. The publish workflow can also be
started manually from the repository's Actions page.

The regression suite also verifies four checksum-pinned public SMTP, IMAP, and
POP3 captures from the Wireshark Foundation SampleCaptures collection. Run
`python tools/validate_public_dataset.py` to reproduce the protocol-transition
validation. See `benchmarks/public-validation.json` for provenance and hashes.

## Monitoring

- Application: `http://localhost:3000`
- API metrics: `http://localhost:8000/metrics`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3001`

Grafana automatically loads the **SecureMailScope Operations** dashboard. Its
admin credentials come from `GRAFANA_ADMIN_USER` and `GRAFANA_ADMIN_PASSWORD`
in `.env`. Liveness is available at `/api/health/live`; readiness, including
PostgreSQL, Redis, TShark, and Zeek, is available at `/api/health/ready`.

## Backup and restore

Create a checksummed PostgreSQL and capture backup. Backups older than 30 days
are removed only from the project-local `backups` directory:

```powershell
.\tools\backup.ps1
```

Verify and restore a backup (this briefly stops application services):

```powershell
.\tools\restore.ps1 -BackupDirectory ".\backups\20260908T120000Z" -ConfirmRestore
```

By default captures are merged. Add `-ReplaceCaptures` only for a full disaster
recovery replacement. Restore always verifies SHA-256 checksums first.

## PostgreSQL persistence

```powershell
docker compose up -d postgres
$env:SECUREMAILSCOPE_DATABASE_URL="postgresql://securemailscope:change-this-before-deployment@localhost:5432/securemailscope"
python -m pip install -r requirements.txt
```

Without `SECUREMAILSCOPE_DATABASE_URL`, the local SQLite database remains the development fallback.

## Background worker

With Redis running locally, start this in a second terminal for queued PCAP jobs:

```powershell
python worker.py
```

Use `POST /api/jobs` to enqueue a PCAP and `GET /api/jobs/{job_id}` to poll `QUEUED`, `RUNNING`, `COMPLETED`, or `FAILED`.

## Zeek phase

Start Docker Desktop, then the optional Zeek worker can run `zeek/zeek:latest` against the same PCAPs and emit JSON `conn`, `ssl`, `x509`, and protocol logs for evidence fusion.
