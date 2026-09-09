from __future__ import annotations

import secrets
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECRET_DIR = ROOT / "secrets"


def token() -> str: return secrets.token_urlsafe(48)


def run(command: list[str], input_text: str | None = None) -> bool:
    result = subprocess.run(command, cwd=ROOT, input=input_text, text=True, capture_output=True, check=False)
    return result.returncode == 0


def main() -> None:
    SECRET_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    values = {"postgres_password.txt": token(), "jwt_secret.txt": token(), "zeek_token.txt": token(), "grafana_password.txt": token()}
    postgres_running = bool(subprocess.run(["docker", "compose", "ps", "-q", "postgres"], cwd=ROOT, capture_output=True, text=True).stdout.strip())
    if postgres_running:
        sql = "ALTER ROLE securemailscope PASSWORD '" + values["postgres_password.txt"] + "';\n"
        if not run(["docker", "compose", "exec", "-T", "postgres", "psql", "-U", "securemailscope", "-d", "securemailscope"], sql): raise RuntimeError("Database password rotation failed; no secret files were changed.")
    grafana_running = bool(subprocess.run(["docker", "compose", "ps", "-q", "grafana"], cwd=ROOT, capture_output=True, text=True).stdout.strip())
    if grafana_running and not run(["docker", "compose", "exec", "-T", "grafana", "grafana", "cli", "admin", "reset-admin-password", values["grafana_password.txt"]]): raise RuntimeError("Grafana password rotation failed; no secret files were changed.")
    for name, value in values.items():
        destination = SECRET_DIR / name; temporary = destination.with_suffix(".tmp")
        temporary.write_text(value + "\n", encoding="utf-8"); temporary.replace(destination)
    print("Generated and rotated four secrets in the ignored secrets directory. Values were not printed.")


if __name__ == "__main__": main()
