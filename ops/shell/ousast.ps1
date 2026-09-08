# OpenUltraSAST as a local command. Dot-source this from your PowerShell profile:
#
#     . C:\path\to\OpenUltraSAST\ops\shell\ousast.ps1
#
# Then use it from any directory:
#
#     ousast scan .
#     ousast scan src\api
#
# Docker is an implementation detail. Your working directory is mounted READ-ONLY and findings are written
# to .\.ousast, the only writable mount.

$script:OusastHome = if ($env:OUSAST_HOME) { $env:OUSAST_HOME }
                     else { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }

function ousast {
    $compose = Join-Path $script:OusastHome 'docker-compose.yml'
    if (-not (Test-Path $compose)) {
        Write-Error "ousast: cannot find $compose (set OUSAST_HOME to the checkout)"; return
    }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Error "ousast: docker is not installed"; return
    }

    $version = if ($env:OUSAST_VERSION) { $env:OUSAST_VERSION } else { 'dev' }
    docker image inspect "openultrasast:$version" *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ousast: building the analysis image once (~2 GB of engine; later runs are instant)"
        Push-Location $script:OusastHome; docker compose build; Pop-Location
    }

    # Rewrite paths under the current directory to their mounted equivalent; leave anything outside alone
    # and say so, rather than silently rewriting it into a path the container cannot see.
    $cwd = (Get-Location).Path
    $mapped = foreach ($a in $args) {
        if (Test-Path $a) {
            $abs = (Resolve-Path $a).Path
            if ($abs -eq $cwd) { '/target' }
            elseif ($abs.StartsWith($cwd)) { '/target' + $abs.Substring($cwd.Length).Replace('\', '/') }
            else { Write-Warning "ousast: $a is outside $cwd and is not mounted"; $a }
        } else { $a }
    }

    New-Item -ItemType Directory -Force -Path (Join-Path $cwd '.ousast') | Out-Null
    $env:TARGET = $cwd
    $env:OUSAST_REPORTS = Join-Path $cwd '.ousast'
    if (-not $env:OUSAST_NETWORK) { $env:OUSAST_NETWORK = 'none' }
    docker compose -f $compose run --rm ousast @mapped
}

# The LLM judge needs network and a key; opt in explicitly.
function ousast-with-judge { $env:OUSAST_NETWORK = 'bridge'; ousast @args }
