# No param() block on purpose: PowerShell would otherwise bind flags meant for
# claude itself (-p, --resume, --bare, ...) against this wrapper's own parameters
# instead of passing them through untouched. Only this wrapper's own switches are
# intercepted (by string match against $args); everything else flows to claude as-is.
$ErrorActionPreference = "Stop"

$ownSwitches = '-StartProxy', '-LocalOnly', '-NoClaudeMd', '-Bare'
$StartProxy = $args -contains '-StartProxy' # accepted for backward compat; now just the default, see below
$LocalOnly = $args -contains '-LocalOnly'
$NoClaudeMd = $args -contains '-NoClaudeMd'
$Bare = $args -contains '-Bare'
$claudeArgs = @($args | Where-Object { $_ -notin $ownSwitches })
if ($Bare) { $claudeArgs = @('--bare') + $claudeArgs }

# Check if a *working* proxy is already running on 8090. A raw port check isn't enough:
# a dead/stale proxy left over from an earlier session can still hold the port without
# ever answering a request, and would otherwise get silently reused.
function Test-ProxyHealthy {
    try { (Invoke-RestMethod "http://127.0.0.1:8090/health" -TimeoutSec 2).status -eq 'ok' } catch { $false }
}

function Ensure-ProxyRunning {
    if (Test-ProxyHealthy) { return }

    # Something may still be bound to the port (a stale proxy); clear it so a fresh one can bind.
    $stale = Get-NetTCPConnection -LocalPort 8090 -State Listen -ErrorAction SilentlyContinue
    if ($stale) {
        Write-Host "Stale process on port 8090 isn't responding; stopping it..."
        $stale.OwningProcess | Sort-Object -Unique | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 1
    }

    Write-Host "Starting proxy server..."
    & (Join-Path $PSScriptRoot "start-proxy.ps1")

    $timeout = 180
    $startTime = Get-Date
    while (-not (Test-ProxyHealthy)) {
        if ((Get-Date) -gt ($startTime.AddSeconds($timeout))) {
            throw "Proxy server failed to start within $timeout seconds"
        }
        Start-Sleep -Seconds 1
    }
}

if ($LocalOnly) {
    # Direct to the local model, no proxy in between: no <system-reminder>
    # sanitization, and no max_tokens ceiling beyond the server's own (unenforced)
    # default -- opt in only when you specifically want zero dependency on the
    # proxy being up. Everything else below goes through it.
    $env:ANTHROPIC_BASE_URL = "http://127.0.0.1:9931"
    $env:ANTHROPIC_API_KEY = if ($Bare) { 'local-no-key' } else { $null }
    $env:ANTHROPIC_AUTH_TOKEN = $null
} elseif ($Bare) {
    # Local-only, routed through the proxy for sanitization: talking directly to
    # 9931 would skip the <system-reminder>/thinking-block stripping the real
    # fallback path already applies, and the local model would otherwise echo
    # injected reminder blocks back into its own output.
    Ensure-ProxyRunning
    $env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8090"
    # --bare only accepts ANTHROPIC_API_KEY. The proxy recognizes this exact dummy
    # key as "skip upstream, sanitize and serve from the local model for every
    # request" (llama-server itself has no key check).
    $env:ANTHROPIC_API_KEY = 'local-no-key'
    $env:ANTHROPIC_AUTH_TOKEN = $null
} else {
    # Default: real Claude via your normal subscription auth, with local fallback
    # available through the proxy ($-prefixed prompts, or an automatic
    # decline-detected fallback). -StartProxy is accepted as an explicit synonym
    # for this, kept for anything that still passes it out of habit.
    Ensure-ProxyRunning
    $env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8090"
    $env:ANTHROPIC_API_KEY = $null
    $env:ANTHROPIC_AUTH_TOKEN = $null
}

# Claude Code assumes a 200K context window for a model name it doesn't recognize
# (or the assumptions of whatever real model it falls back to display instead) --
# tell it the local server's real budget so auto-compact triggers before the
# request actually exceeds it. Only relevant when the local model is actually
# what's answering (Bare or LocalOnly); the default hybrid path talks to the real
# API, which Claude Code already knows the real limits for.
$originalMaxContext = $env:CLAUDE_CODE_MAX_CONTEXT_TOKENS
if ($Bare -or $LocalOnly) {
    try {
        $localCtx = (Invoke-RestMethod "http://127.0.0.1:9931/props" -TimeoutSec 5).default_generation_settings.n_ctx
    } catch { $localCtx = $null }
    $env:CLAUDE_CODE_MAX_CONTEXT_TOKENS = if ($localCtx) { "$localCtx" } else { $null }
}

# Run Claude Code with appropriate config
$originalConfigDir = $env:CLAUDE_CONFIG_DIR
$env:CLAUDE_CONFIG_DIR = $null # Use default config dir with subscription login
$originalNoClaudeMd = $env:CLAUDE_CODE_DISABLE_CLAUDE_MDS
# Undocumented env var, verified working on Claude Code 2.1.283; re-check after updates.
$env:CLAUDE_CODE_DISABLE_CLAUDE_MDS = if ($NoClaudeMd) { '1' } else { $null }

try {
    Write-Host "Starting Claude Code..."
    & "claude" @claudeArgs
}
finally {
    # Restore original config dir
    $env:CLAUDE_CONFIG_DIR = $originalConfigDir
    $env:CLAUDE_CODE_DISABLE_CLAUDE_MDS = $originalNoClaudeMd
    $env:CLAUDE_CODE_MAX_CONTEXT_TOKENS = $originalMaxContext

    # Clean up environment variables -- every branch above sets these, so a plain
    # `claude` run afterward in the same terminal isn't left pointed at either server.
    Remove-Item Env:\ANTHROPIC_BASE_URL -ErrorAction SilentlyContinue
    Remove-Item Env:\ANTHROPIC_API_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:\ANTHROPIC_AUTH_TOKEN -ErrorAction SilentlyContinue
}