param(
    [string]$BackupRoot = "backups",
    [int]$RetentionDays = 30
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location -LiteralPath $ProjectRoot
$BackupRootPath = [IO.Path]::GetFullPath((Join-Path $ProjectRoot $BackupRoot))
if (-not $BackupRootPath.StartsWith($ProjectRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "BackupRoot must stay inside the project directory."
}

$Stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$Destination = Join-Path $BackupRootPath $Stamp
New-Item -ItemType Directory -Path $Destination -Force | Out-Null

$DatabaseTemp = "/tmp/securemailscope-$Stamp.dump"
$ApiContainer = docker compose ps -q api
if (-not $ApiContainer) { throw "The API container must be running so its capture volume can be identified." }
$ContainerInfo = docker inspect $ApiContainer | ConvertFrom-Json
$CaptureVolume = ($ContainerInfo[0].Mounts | Where-Object { $_.Destination -eq "/app/data" }).Name
if (-not $CaptureVolume) { throw "Capture volume could not be identified." }
try {
    docker compose exec -T postgres pg_dump -U securemailscope -d securemailscope -Fc -f $DatabaseTemp
    if ($LASTEXITCODE -ne 0) { throw "PostgreSQL backup failed." }
    docker compose cp "postgres:$DatabaseTemp" (Join-Path $Destination "postgres.dump")
    if ($LASTEXITCODE -ne 0) { throw "Could not copy the PostgreSQL backup." }

    docker run --rm --mount "type=volume,source=$CaptureVolume,target=/data,readonly" --mount "type=bind,source=$Destination,target=/backup" python:3.13-slim tar -czf /backup/captures.tar.gz -C /data captures
    if ($LASTEXITCODE -ne 0) { throw "Capture archive failed." }
}
finally {
    docker compose exec -T postgres rm -f -- $DatabaseTemp 2>$null
}

$Files = Get-ChildItem -LiteralPath $Destination -File | ForEach-Object {
    $Hash = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
    [ordered]@{ file = $_.Name; bytes = $_.Length; sha256 = $Hash.Hash.ToLowerInvariant() }
}
$Manifest = [ordered]@{ created_at = (Get-Date).ToUniversalTime().ToString("o"); format_version = 1; files = @($Files) }
$Manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $Destination "manifest.json") -Encoding utf8

if ($RetentionDays -gt 0) {
    $Cutoff = (Get-Date).ToUniversalTime().AddDays(-$RetentionDays)
    Get-ChildItem -LiteralPath $BackupRootPath -Directory | Where-Object {
        $_.Name -match '^\d{8}T\d{6}Z$' -and $_.LastWriteTimeUtc -lt $Cutoff -and $_.Parent.FullName -eq $BackupRootPath
    } | Remove-Item -Recurse -Force
}

Write-Host "Backup created: $Destination"
Get-Content -LiteralPath (Join-Path $Destination "manifest.json")
