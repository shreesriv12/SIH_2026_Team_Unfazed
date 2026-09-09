# Run in an elevated PowerShell after installing Wireshark/Npcap.
# Creates golden fixtures one scenario at a time using the controlled local labs.
param([ValidateSet("smtp-ignored","smtp-plain","smtp-rejected","smtp-broken","imap-broken","pop3-broken")][string]$Scenario)
$root = (Split-Path $PSScriptRoot -Parent)
$pcapDirectory = Join-Path $root "pcaps"
$tshark = "C:\Program Files\Wireshark\tshark.exe"
$labScript = Join-Path $PSScriptRoot "smtp_starttls_lab.py"
$map = @{"smtp-ignored"=@(2529,"server-ignored","client-ignored","smtp_starttls_ignored.pcapng",$labScript); "smtp-plain"=@(2526,"server-plain","client-plain","smtp_plain.pcapng",$labScript); "smtp-rejected"=@(2527,"server-reject","client-reject","smtp_starttls_rejected.pcapng",$labScript); "smtp-broken"=@(2528,"server-broken","client-broken","smtp_starttls_broken.pcapng",$labScript)}
if (!$map.ContainsKey($Scenario)) { throw "Use the dedicated mail_upgrade_lab.py commands for IMAP/POP3 fixtures." }
$item=$map[$Scenario]; New-Item -ItemType Directory -Force $pcapDirectory | Out-Null
$output = Join-Path $pcapDirectory $item[3]
$capture=Start-Process -FilePath $tshark -ArgumentList "-i 8 -f `"tcp port $($item[0])`" -a duration:8 -w `"$output`"" -PassThru
Start-Sleep 3; $server=Start-Job -ScriptBlock { param($scriptPath, $mode) & python $scriptPath $mode } -ArgumentList $item[4], $item[1]; Start-Sleep 1
& python $item[4] $item[2]; Wait-Job $server -Timeout 10 | Out-Null; Receive-Job $server; Remove-Job $server; $capture.WaitForExit()
if (!(Test-Path $output) -or (Get-Item $output).Length -lt 100) { throw "Capture failed; no packets were written. Ensure TShark interface 8 is the loopback adapter." }
Write-Host "Created $output"
