# V.1 test runner - fixture-driven detection tests
#
# REQUIREMENTS:
# - Runs on Windows with administrative elevation (for cross-process memory scanning)
# - Tests memory injection heuristics by running fixtures and scanning the process
#
# Usage: .\run.ps1 [-FixtureName name] [-Verbose]
#        .\run.ps1 -ListOnly         (list available fixtures)

param(
    [string]$FixtureName = "",
    [switch]$ListOnly = $false,
    [switch]$Verbose = $false
)

$harness = Join-Path $PSScriptRoot "harness-v3.ps1"
& $harness -FixtureName $FixtureName -ListOnly:$ListOnly -Verbose:$Verbose
exit $LASTEXITCODE
