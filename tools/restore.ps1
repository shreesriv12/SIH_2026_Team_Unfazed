param(
    [Parameter(Mandatory = $true)][string]$BackupDirectory,
    [switch]$ConfirmRestore,
    [switch]$ReplaceCaptures
)

$ErrorActionPreference = "Stop"
if (-not $ConfirmRestore) { throw "Restore changes production data. Re-run with -ConfirmRestore after verifying the target environment." }
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location -LiteralPath $ProjectRoot
$BackupPath = (Resolve-Path -LiteralPath $BackupDirectory).Path
$ManifestPath = Join-Path $BackupPath "manifest.json"
if (-not (Test-Path -LiteralPath $ManifestPath)) { throw "manifest.json was not found." }

$Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
foreach ($Entry in $Manifest.files) {
    $FilePath = Join-Path $BackupPath $Entry.file
    if (-not (Test-Path -LiteralPath $FilePath)) { throw "Backup file missing: $($Entry.file)" }
    $Actual = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Actual -ne $Entry.sha256) { throw "Checksum mismatch: $($Entry.file)" }
}

$ApiContainer = docker compose ps -q api
if (-not $ApiContainer) { throw "Start the stack once so the capture volume can be identified." }
$ContainerInfo = docker inspect $ApiContainer | ConvertFrom-Json
$CaptureVolume = ($ContainerInfo[0].Mounts | Where-Object { $_.Destination -eq "/app/data" }).Name
if (-not $CaptureVolume) { throw "Capture volume could not be identified." }

docker compose stop frontend api worker zeek
$DatabaseTemp = "/tmp/securemailscope-restore.dump"
try {
    docker compose cp (Join-Path $BackupPath "postgres.dump") "postgres:$DatabaseTemp"
    docker compose exec -T postgres pg_restore -U securemailscope -d securemailscope --clean --if-exists --no-owner $DatabaseTemp
    if ($LASTEXITCODE -ne 0) { throw "PostgreSQL restore failed." }

    if ($ReplaceCaptures) {
        docker run --rm --mount "type=volume,source=$CaptureVolume,target=/data" python:3.13-slim sh -c "test -d /data/captures && find /data/captures -mindepth 1 -maxdepth 1 -delete || true"
        if ($LASTEXITCODE -ne 0) { throw "Existing capture cleanup failed." }
    }
    docker run --rm --mount "type=volume,source=$CaptureVolume,target=/data" --mount "type=bind,source=$BackupPath,target=/backup,readonly" python:3.13-slim tar -xzf /backup/captures.tar.gz -C /data
    if ($LASTEXITCODE -ne 0) { throw "Capture restore failed." }
}
finally {
    docker compose exec -T postgres rm -f -- $DatabaseTemp 2>$null
    docker compose up -d
}
Write-Host "Restore completed and services restarted."
