<#
.SYNOPSIS
    Build a loadable copy of the extension pointed at your own server.

.DESCRIPTION
    The extension decides what it may contact from its own manifest, and the
    manifest in this repository names a placeholder host. That is deliberate:
    widening where real values may be sent has to be a manifest change rather
    than a settings field, and the published repository must not carry one
    organisation's hostnames.

    So the copy you load is generated, not edited in place. Editing the
    checked-in manifest would put your host in a public tree and would be
    undone by the next pull; a copy made once by hand goes stale silently as
    the extension changes. Re-run this after every pull and load the result.

    The copy lands OUTSIDE the repository, so git never sees it.

.PARAMETER VaultUrl
    Your Claudefuscator server, e.g. https://vault.example.com. Must be https
    unless it is loopback - the manifest is what stops the extension sending
    real values somewhere unencrypted.

.PARAMETER Destination
    Where to write the copy. Defaults to ~/.claudefuscator/extension.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\make-local-extension.ps1 `
        -VaultUrl https://vault.example.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $VaultUrl,
    [string] $Destination = (Join-Path $env:USERPROFILE '.claudefuscator\extension')
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$source = Join-Path $repoRoot 'chrome-extension'
if (-not (Test-Path (Join-Path $source 'manifest.json'))) {
    throw "No extension at $source. Run this from a checkout of the repository."
}

$url = $VaultUrl.Trim().TrimEnd('/')
$parsed = [Uri] $url
if ($parsed.Scheme -ne 'https' -and
    $parsed.Host -notin @('127.0.0.1', 'localhost', '::1')) {
    throw "Refusing $url - must be https unless it is loopback. The manifest is what keeps real values off an unencrypted hop."
}
$origin = '{0}://{1}{2}' -f $parsed.Scheme, $parsed.Host,
    $(if ($parsed.IsDefaultPort) { '' } else { ':' + $parsed.Port })

# Rebuilt from scratch rather than copied over: a stale file left behind by
# a previous run is a file Chrome still loads.
if (Test-Path $Destination) { Remove-Item -Recurse -Force $Destination }
New-Item -ItemType Directory -Force -Path $Destination | Out-Null
Copy-Item -Path (Join-Path $source '*') -Destination $Destination -Recurse -Force

$manifestPath = Join-Path $Destination 'manifest.json'
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json

# Keep every loopback entry, drop any other, add this one. Replacing the
# whole list rather than appending means running this twice does not
# accumulate origins, and a placeholder never survives into the copy.
$loopback = @($manifest.host_permissions | Where-Object {
    $_ -match '^https?://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?/\*$'
})
$manifest.host_permissions = @($loopback) + @("$origin/*")

$connectSrc = (@("'self'") + @($loopback | ForEach-Object { $_ -replace '/\*$', '' }) + @($origin)) -join ' '
$manifest.content_security_policy.extension_pages =
    "script-src 'self'; object-src 'self'; connect-src $connectSrc"

$manifest | ConvertTo-Json -Depth 20 | Set-Content $manifestPath -Encoding UTF8

Write-Host "Built a local copy of the extension." -ForegroundColor Green
Write-Host "  from   : $source"
Write-Host "  to     : $Destination"
Write-Host "  reaches: $($manifest.host_permissions -join ', ')"
Write-Host ''
Write-Host 'Load it: chrome://extensions, Developer mode, Load unpacked, pick'
Write-Host "  $Destination"
Write-Host ''
Write-Host 'This copy is outside the repository, so git never sees your host.'
Write-Host 'Re-run after pulling, or the copy drifts from the extension.'
