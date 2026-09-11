#Requires -Version 5.1
<#
.SYNOPSIS
    Polymorphic build driver for JOCKY.

.DESCRIPTION
    Compiles a .jk source file with --polymorphic (a fresh crypto-random seed
    each run), SHA-256 hashes the output binary, and records the result in
    build-artifacts/manifest.json. Exits with code 1 if the hash collides with
    a previous build (should never happen) or if the compiler fails.

.PARAMETER Source
    Path to the .jk source file to compile.

.PARAMETER OutDir
    Directory where the compiled binary is written. Created if absent.
    Default: build\out

.PARAMETER BuildDir
    Directory containing the compiled jocky.exe. Default: build

.EXAMPLE
    .\scripts\ci-build.ps1 -Source forensic\mem\jocky-mem.jk
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Source,

    [string]$OutDir = "build\out",

    [string]$BuildDir = "build"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Resolve paths ──────────────────────────────────────────────────────────────

$repoRoot   = Split-Path -Parent $PSScriptRoot
$sourcePath = Join-Path $repoRoot $Source
$outDirPath = Join-Path $repoRoot $OutDir
$jockyExe   = Join-Path $repoRoot $BuildDir "jocky.exe"
$manifestPath = Join-Path $repoRoot "build-artifacts" "manifest.json"

if (-not (Test-Path $sourcePath)) {
    Write-Error "Source file not found: $sourcePath"
    exit 1
}
if (-not (Test-Path $jockyExe)) {
    Write-Error "jocky.exe not found at: $jockyExe (run cmake --build first)"
    exit 1
}
if (-not (Test-Path $outDirPath)) {
    New-Item -ItemType Directory -Path $outDirPath | Out-Null
}

# ── Generate a 64-bit crypto-random seed ──────────────────────────────────────

$rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 8
$rng.GetBytes($bytes)
$seed  = [System.BitConverter]::ToUInt64($bytes, 0)

# ── Derive output binary name ─────────────────────────────────────────────────

$baseName  = [System.IO.Path]::GetFileNameWithoutExtension($Source)
$outBinary = Join-Path $outDirPath "$baseName.exe"

# ── Compile ───────────────────────────────────────────────────────────────────

Write-Host "[ci-build] Compiling $Source with seed=$seed ..."

& $jockyExe build --polymorphic -O1 --obf-seed $seed `
    -o $outBinary $sourcePath

if ($LASTEXITCODE -ne 0) {
    Write-Error "jocky build failed (exit $LASTEXITCODE)"
    exit 1
}

# ── Hash the binary ───────────────────────────────────────────────────────────

$hashResult = Get-FileHash -Path $outBinary -Algorithm SHA256
$sha256     = $hashResult.Hash.ToLower()

Write-Host "[ci-build] Binary hash: $sha256"

# ── Load / create manifest and check for collisions ───────────────────────────

$manifestDir = Split-Path -Parent $manifestPath
if (-not (Test-Path $manifestDir)) {
    New-Item -ItemType Directory -Path $manifestDir | Out-Null
}

$entries = @()
if (Test-Path $manifestPath) {
    $raw = Get-Content -Path $manifestPath -Raw
    if ($raw.Trim()) {
        $entries = $raw | ConvertFrom-Json
        # ConvertFrom-Json returns a PSCustomObject for a single item; normalise.
        if ($entries -isnot [System.Array]) { $entries = @($entries) }
    }
}

$collision = $entries | Where-Object { $_.sha256 -eq $sha256 }
if ($collision) {
    Write-Error "COLLISION: hash $sha256 already appears in manifest (seed $($collision.seed))"
    exit 1
}

# ── Append new entry ──────────────────────────────────────────────────────────

$newEntry = [ordered]@{
    timestamp = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
    seed      = $seed
    target    = [System.IO.Path]::GetFileName($outBinary)
    sha256    = $sha256
}
$entries += $newEntry

$entries | ConvertTo-Json -Depth 3 | Set-Content -Path $manifestPath -Encoding utf8

# ── Done ──────────────────────────────────────────────────────────────────────

Write-Host "[BUILD OK] seed=$seed sha256=$sha256"
Write-Host "           binary: $outBinary"
Write-Host "           manifest: $manifestPath  ($($entries.Count) total entries)"
