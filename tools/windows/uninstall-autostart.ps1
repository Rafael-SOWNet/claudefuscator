<#
.SYNOPSIS
    Stop starting the Claudefuscator agent at logon, and remove the shim.

.DESCRIPTION
    Removes the scheduled task and the generated launcher. Leaves the agent's
    state alone - the stored vault credential, the identifier list and the
    discovered-value cache are not this script's to delete, and somebody
    turning off auto-start has not asked to be disconnected.

    Use the agent's own --disconnect to forget the credential.
#>
[CmdletBinding()]
param([string] $TaskName = 'Claudefuscator agent')

$ErrorActionPreference = 'Stop'

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed the scheduled task '$TaskName'." -ForegroundColor Green
} else {
    Write-Host "No scheduled task named '$TaskName'."
}

$vbs = Join-Path $env:USERPROFILE '.claudefuscator\start-agent.vbs'
if (Test-Path $vbs) {
    Remove-Item $vbs
    Write-Host "Removed the launcher $vbs."
}

Write-Host ''
Write-Host 'The agent itself may still be running. Close it, or:'
Write-Host '  Get-CimInstance Win32_Process -Filter "Name like ''%python%''" |'
Write-Host '    Where-Object { $_.CommandLine -like "*claudefuscator_agent.py*" } |'
Write-Host '    ForEach-Object { Stop-Process -Id $_.ProcessId }'
Write-Host ''
Write-Host 'Your vault credential is untouched. Forget it with:'
Write-Host '  python agent\claudefuscator_agent.py --disconnect'
