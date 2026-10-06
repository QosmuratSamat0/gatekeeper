<#
.SYNOPSIS
    Local development helper script for Gatekeeper Auth Service.

.DESCRIPTION
    Loads environment variables from a local .env file into the process environment,
    runs the HTTP API service or applies database migrations, and restores all
    original environment variables upon exit.
    Configuration is read by Go binaries via standard os.Getenv; no .env loading
    is embedded in production Go code.

.PARAMETER Command
    The action to execute: 'api' to run the HTTP service, or 'migrate' to run schema migrations.

.PARAMETER CommandArgs
    Additional arguments passed to the command (e.g., 'up' or 'version' for migrate).

.PARAMETER EnvFile
    Optional custom path to the .env file. Defaults to '.env' in the auth service directory.

.PARAMETER GoCache
    Optional path to the Go build cache. Defaults to '.gocache' in the repository root.

.EXAMPLE
    .\run.ps1 api
    .\run.ps1 migrate up
    .\run.ps1 migrate version
#>

[CmdletBinding()]
param (
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet("api", "migrate")]
    [string]$Command,

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$CommandArgs,

    [Parameter()]
    [string]$EnvFile = "",

    [Parameter()]
    [string]$GoCache = ""
)

$ErrorActionPreference = "Stop"

# Track original environment state so modifications never pollute the calling PowerShell session.
$script:savedEnv = @{}

function Set-ProcessEnvIsolated {
    param (
        [string]$Key,
        [string]$Value
    )

    # Save original variable state before first modification
    if (-not $script:savedEnv.ContainsKey($Key)) {
        $existing = [System.Environment]::GetEnvironmentVariable($Key, [System.EnvironmentVariableTarget]::Process)
        $script:savedEnv[$Key] = $existing
    }

    [System.Environment]::SetEnvironmentVariable($Key, $Value, [System.EnvironmentVariableTarget]::Process)
}

function Restore-ProcessEnv {
    # Restore each modified variable to its prior state or remove if it was not originally set
    foreach ($k in $script:savedEnv.Keys) {
        $orig = $script:savedEnv[$k]
        [System.Environment]::SetEnvironmentVariable($k, $orig, [System.EnvironmentVariableTarget]::Process)
    }
    $script:savedEnv.Clear()
}

# Determine directory paths relative to this script location
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRootDir = Split-Path -Parent (Split-Path -Parent $scriptDir)

$scriptExitCode = 0

try {
    # 1. Configure Go compilation cache separately from Auth service configuration.
    # Set cache via isolated environment wrapper to restore original state on exit.
    if ([string]::IsNullOrWhiteSpace($GoCache)) {
        if (-not [string]::IsNullOrWhiteSpace($env:GOCACHE)) {
            $GoCache = $env:GOCACHE
        } else {
            $GoCache = Join-Path $repoRootDir ".gocache"
        }
    }

    if (-not (Test-Path -LiteralPath $GoCache)) {
        New-Item -ItemType Directory -Force -Path $GoCache | Out-Null
    }
    $resolvedGoCache = (Resolve-Path -LiteralPath $GoCache).Path
    Set-ProcessEnvIsolated -Key "GOCACHE" -Value $resolvedGoCache

    # 2. Parse .env file securely without Invoke-Expression.
    # Supported format:
    #   - Empty lines and lines starting with '#' are ignored as comments.
    #   - Key-value pairs separated by '=': KEY=VALUE.
    #   - Keys must match [A-Za-z_][A-Za-z0-9_]*.
    #   - Values may be unquoted, or enclosed in matching single ('...') or double ("...") quotes.
    #   - Any unclosed or mismatched quotes (including solitary quotes like KEY=") trigger a syntax error.
    #   - Malformed lines fail with the line number; line contents and values are masked for security.
    if ([string]::IsNullOrWhiteSpace($EnvFile)) {
        $EnvFile = Join-Path $scriptDir ".env"
    }

    if (Test-Path -LiteralPath $EnvFile) {
        $lines = Get-Content -LiteralPath $EnvFile -Encoding UTF8
        $lineNum = 0

        foreach ($line in $lines) {
            $lineNum++
            $trimmed = $line.Trim()

            # Ignore empty lines and comment lines
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith("#")) {
                continue
            }

            # Split at the first '=' character so values containing '=' (such as query strings) remain intact
            $equalsIndex = $trimmed.IndexOf('=')
            if ($equalsIndex -le 0) {
                throw "Invalid .env format at line $lineNum in '$EnvFile': expected KEY=VALUE syntax. (Line contents hidden for security)"
            }

            $key = $trimmed.Substring(0, $equalsIndex).Trim()
            $val = $trimmed.Substring($equalsIndex + 1).Trim()

            # Validate that the variable key is a valid alphanumeric identifier
            if ($key -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
                throw "Invalid environment variable name at line $lineNum in '$EnvFile'. (Line contents hidden for security)"
            }

            # Validate and strip surrounding quotes.
            # Handles solitary quote characters (e.g. KEY="), unclosed quotes, and mismatched quotes.
            $hasLeadingQuote = ($val.Length -ge 1) -and ($val[0] -eq '"' -or $val[0] -eq "'")
            $hasTrailingQuote = ($val.Length -ge 1) -and ($val[$val.Length - 1] -eq '"' -or $val[$val.Length - 1] -eq "'")

            if ($hasLeadingQuote -or $hasTrailingQuote) {
                if ($val.Length -ge 2 -and (
                    ($val[0] -eq '"' -and $val[$val.Length - 1] -eq '"') -or
                    ($val[0] -eq "'" -and $val[$val.Length - 1] -eq "'")
                )) {
                    # Strip matching surrounding quotes
                    $val = $val.Substring(1, $val.Length - 2)
                } else {
                    throw "Mismatched or unclosed quotes around value at line $lineNum in '$EnvFile'. (Line contents hidden for security)"
                }
            }

            Set-ProcessEnvIsolated -Key $key -Value $val
        }
    } else {
        Write-Host "Notice: No .env file found at '$EnvFile'. Using existing environment variables." -ForegroundColor Yellow
    }

    # 3. Execute requested command in the auth service directory
    Push-Location $scriptDir
    try {
        switch ($Command) {
            "api" {
                Write-Host "Starting Gatekeeper Auth Service API..." -ForegroundColor Cyan
                go run ./cmd/api
                $scriptExitCode = $LASTEXITCODE
            }
            "migrate" {
                if (-not $CommandArgs -or $CommandArgs.Length -eq 0) {
                    Write-Host "Usage: .\run.ps1 migrate <up|version>" -ForegroundColor Yellow
                    $scriptExitCode = 1
                } else {
                    Write-Host "Running migrations: $($CommandArgs -join ' ')..." -ForegroundColor Cyan
                    go run ./cmd/migrate @CommandArgs
                    $scriptExitCode = $LASTEXITCODE
                }
            }
        }
    } finally {
        Pop-Location
    }
} catch {
    Write-Error $_
    $scriptExitCode = 1
} finally {
    # Always restore parent PowerShell environment variables, even on parsing error or command abort
    Restore-ProcessEnv
}

if ($scriptExitCode -ne 0) {
    exit $scriptExitCode
}
