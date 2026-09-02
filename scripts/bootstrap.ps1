<#
.SYNOPSIS
    Jocky project bootstrap for Windows 11.

.DESCRIPTION
    1. Installs system dependencies via winget (Git, CMake, Python, Visual Studio
       Build Tools) and vcpkg (OpenSSL, libcurl, SQLite)
    2. Provisions LLVM (>= $LlvmMinVersion) - prebuilt release archive by default,
       or built from source with -FromSource
    3. Sets JOCKY_ROOT, LLVM_DIR, and related environment variables (persisted
       for the current user, and written to .jocky-env.ps1 for easy re-sourcing)
    4. Runs CMake to configure the project build directory

.PARAMETER FromSource
    Build LLVM from source instead of downloading a prebuilt release archive.
    Slow: expect 1-3+ hours and significant disk/RAM usage. Requires Visual
    Studio's C++ toolchain and Ninja.

.PARAMETER Release
    Configure CMake in Release mode (default: Debug).

.PARAMETER LlvmVersion
    LLVM version to install (default: 18.1.8). Must be >= 16.

.PARAMETER SkipSystemDeps
    Skip the winget/vcpkg install step (useful for re-runs).

.PARAMETER SkipCMake
    Provision only; don't run the CMake configure step.

.PARAMETER Force
    Re-install/rebuild steps even if outputs already exist.

.EXAMPLE
    .\bootstrap.ps1
    .\bootstrap.ps1 -FromSource
    .\bootstrap.ps1 -Release -LlvmVersion 17.0.6
    .\bootstrap.ps1 -SkipSystemDeps -SkipCMake
#>

[CmdletBinding()]
param(
    [switch]$FromSource,
    [switch]$Release,
    [string]$LlvmVersion = "18.1.8",
    [switch]$SkipSystemDeps,
    [switch]$SkipCMake,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Log     { param([string]$Message) Write-Host "[bootstrap] $Message" -ForegroundColor Cyan }
function Write-WarnLog { param([string]$Message) Write-Host "[bootstrap][warn] $Message" -ForegroundColor Yellow }
function Write-ErrLog  { param([string]$Message) Write-Host "[bootstrap][error] $Message" -ForegroundColor Red }

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-ErrLog "This script must be run from an elevated (Administrator) PowerShell prompt."
        exit 1
    }
}

$LlvmMinVersion = 16
$LlvmMajor = [int]($LlvmVersion.Split('.')[0])
if ($LlvmMajor -lt $LlvmMinVersion) {
    Write-ErrLog "-LlvmVersion $LlvmVersion is below the required minimum major version ($LlvmMinVersion)."
    exit 1
}

$CMakeBuildType = if ($Release) { "Release" } else { "Debug" }

$ScriptDir             = Split-Path -Parent $MyInvocation.MyCommand.Path
$JockyRoot             = Split-Path -Parent $ScriptDir
$JockyVendorDir        = Join-Path $JockyRoot ".vendor"
$JockyLlvmSrcDir       = Join-Path $JockyVendorDir "llvm-project"
$JockyLlvmBuildDir     = Join-Path $JockyVendorDir "llvm-build"
$JockyLlvmInstallDir   = Join-Path $JockyVendorDir "llvm-install-$LlvmVersion"
$JockyBuildDir         = Join-Path $JockyRoot "build"
$VcpkgDir              = Join-Path $JockyVendorDir "vcpkg"
$EnvFile               = Join-Path $JockyRoot ".jocky-env.ps1"

New-Item -ItemType Directory -Force -Path $JockyVendorDir | Out-Null

function Install-SystemDeps {
    Write-Log "Installing system dependencies via winget."

    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-ErrLog "winget not found. Install 'App Installer' from the Microsoft Store, then re-run."
        exit 1
    }

    $wingetPackages = @(
        "Git.Git",
        "Kitware.CMake",
        "Python.Python.3.12"
    )
    foreach ($pkg in $wingetPackages) {
        Write-Log "  winget install $pkg"
        winget install --id $pkg -e --source winget --accept-package-agreements --accept-source-agreements --silent
    }

    Write-Log "  winget install Visual Studio 2022 Build Tools (C++ workload) -- this step is large and can take a while"
    winget install --id Microsoft.VisualStudio.2022.BuildTools -e --source winget `
        --accept-package-agreements --accept-source-agreements --silent `
        --override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive --norestart"

    Write-Log "System dependencies installed via winget."

    if (-not (Test-Path $VcpkgDir)) {
        Write-Log "Cloning vcpkg."
        git clone https://github.com/microsoft/vcpkg.git $VcpkgDir
    } else {
        Write-Log "vcpkg already present at $VcpkgDir, skipping clone."
    }

    $vcpkgExe = Join-Path $VcpkgDir "vcpkg.exe"
    if (-not (Test-Path $vcpkgExe)) {
        Write-Log "Bootstrapping vcpkg."
        & (Join-Path $VcpkgDir "bootstrap-vcpkg.bat") -disableMetrics
    }

    Write-Log "Installing OpenSSL, libcurl, SQLite via vcpkg (x64-windows)."
    & $vcpkgExe install openssl:x64-windows curl:x64-windows sqlite3:x64-windows
    & $vcpkgExe integrate install

    Write-Log "vcpkg dependencies installed."
}

if (-not $SkipSystemDeps) {
    Assert-Admin
    Install-SystemDeps
} else {
    Write-Log "Skipping system dependency install (-SkipSystemDeps)."
}

$LlvmDirResolved = $null
$LlvmRootResolved = $null

function Install-LlvmPrebuilt {
    Write-Log "Installing prebuilt LLVM $LlvmVersion."

    $installDir = "C:\Program Files\LLVM"
    $clangExe = Join-Path $installDir "bin\clang.exe"

    if ((Test-Path $clangExe) -and (-not $Force)) {
        Write-Log "LLVM already installed at $installDir, skipping (use -Force to reinstall)."
    } else {
        $assetName = "LLVM-$LlvmVersion-win64.exe"
        $url = "https://github.com/llvm/llvm-project/releases/download/llvmorg-$LlvmVersion/$assetName"
        $installerPath = Join-Path $JockyVendorDir $assetName

        Write-Log "Downloading $url ."
        try {
            Invoke-WebRequest -Uri $url -OutFile $installerPath -UseBasicParsing
        } catch {
            Write-WarnLog "Pinned-version download failed ($($_.Exception.Message)). Falling back to winget's latest LLVM package."
            winget install --id LLVM.LLVM -e --source winget --accept-package-agreements --accept-source-agreements --silent
        }

        if (Test-Path $installerPath) {
            Write-Log "Running LLVM installer silently (requires admin)."
            Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait
        }
    }

    if (-not (Test-Path $clangExe)) {
        $found = Get-ChildItem -Path "C:\Program Files*", "$env:LOCALAPPDATA\Programs" -Filter "clang.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            $installDir = Split-Path -Parent (Split-Path -Parent $found.FullName)
        } else {
            Write-ErrLog "Could not locate clang.exe after installation. Check the LLVM install manually."
            exit 1
        }
    }

    $llvmDirCandidate = Join-Path $installDir "lib\cmake\llvm"
    if (-not (Test-Path $llvmDirCandidate)) {
        Write-WarnLog "LLVM cmake config not found at $llvmDirCandidate. The official installer may not ship it -- consider -FromSource if find_package(LLVM) fails."
    }

    $script:LlvmDirResolved = $llvmDirCandidate
    $script:LlvmRootResolved = $installDir
    Write-Log "Prebuilt LLVM ready. LLVM_ROOT=$installDir"
}

function Build-LlvmFromSource {
    Write-Log "Building LLVM $LlvmVersion from source. This will take a while (1-3+ hours, ~30GB disk, lots of RAM)."

    $llvmConfigCmake = Join-Path $JockyLlvmInstallDir "lib\cmake\llvm\LLVMConfig.cmake"
    if ((Test-Path $llvmConfigCmake) -and (-not $Force)) {
        Write-Log "LLVM already built at $JockyLlvmInstallDir, skipping (use -Force to rebuild)."
        $script:LlvmDirResolved = Join-Path $JockyLlvmInstallDir "lib\cmake\llvm"
        $script:LlvmRootResolved = $JockyLlvmInstallDir
        return
    }

    if (-not (Test-Path $JockyLlvmSrcDir)) {
        $branch = "release/$($LlvmVersion.Split('.')[0]).x"
        Write-Log "Cloning llvm-project (branch $branch, shallow)."
        git clone --depth 1 --branch $branch https://github.com/llvm/llvm-project.git $JockyLlvmSrcDir
    } else {
        Write-Log "llvm-project source already present at $JockyLlvmSrcDir, reusing."
    }

    if (-not (Get-Command ninja -ErrorAction SilentlyContinue)) {
        Write-Log "Installing Ninja via winget."
        winget install --id Ninja-build.Ninja -e --source winget --accept-package-agreements --accept-source-agreements --silent
    }

    New-Item -ItemType Directory -Force -Path $JockyLlvmBuildDir | Out-Null

    Write-Log "Configuring LLVM build (this alone can take several minutes)."
    Write-Log "NOTE: run this from a 'x64 Native Tools Command Prompt for VS 2022' if cl.exe / Ninja can't find the MSVC toolchain."
    cmake -S (Join-Path $JockyLlvmSrcDir "llvm") -B $JockyLlvmBuildDir -G Ninja `
        -DCMAKE_BUILD_TYPE=Release `
        "-DCMAKE_INSTALL_PREFIX=$JockyLlvmInstallDir" `
        -DLLVM_ENABLE_PROJECTS="clang;lld" `
        -DLLVM_TARGETS_TO_BUILD="X86;AArch64" `
        -DLLVM_ENABLE_ASSERTIONS=OFF `
        -DLLVM_INCLUDE_TESTS=OFF `
        -DLLVM_INCLUDE_EXAMPLES=OFF `
        -DLLVM_INCLUDE_BENCHMARKS=OFF

    $jobs = $env:NUMBER_OF_PROCESSORS
    Write-Log "Building LLVM with $jobs parallel jobs."
    cmake --build $JockyLlvmBuildDir -j $jobs

    Write-Log "Installing LLVM into $JockyLlvmInstallDir."
    cmake --install $JockyLlvmBuildDir

    $script:LlvmDirResolved = Join-Path $JockyLlvmInstallDir "lib\cmake\llvm"
    $script:LlvmRootResolved = $JockyLlvmInstallDir
    Write-Log "LLVM built from source. LLVM_DIR=$($script:LlvmDirResolved)"
}

if ($FromSource) {
    Build-LlvmFromSource
} else {
    Install-LlvmPrebuilt
}

Write-Log "Writing environment file to $EnvFile"

$envFileContent = @"
# Auto-generated by bootstrap.ps1 on $((Get-Date).ToUniversalTime().ToString("o"))
# Dot-source this file to load project env vars into your current session:
#   . "$EnvFile"
`$env:JOCKY_ROOT     = "$JockyRoot"
`$env:JOCKY_BUILD_DIR = "$JockyBuildDir"
`$env:LLVM_VERSION   = "$LlvmVersion"
`$env:LLVM_DIR       = "$LlvmDirResolved"
`$env:LLVM_ROOT      = "$LlvmRootResolved"
`$env:VCPKG_ROOT     = "$VcpkgDir"
`$env:Path           = "$LlvmRootResolved\bin;" + `$env:Path
"@
Set-Content -Path $EnvFile -Value $envFileContent -Encoding utf8

[Environment]::SetEnvironmentVariable("JOCKY_ROOT", $JockyRoot, "User")
[Environment]::SetEnvironmentVariable("LLVM_DIR", $LlvmDirResolved, "User")
[Environment]::SetEnvironmentVariable("LLVM_ROOT", $LlvmRootResolved, "User")
[Environment]::SetEnvironmentVariable("VCPKG_ROOT", $VcpkgDir, "User")

$env:JOCKY_ROOT = $JockyRoot
$env:LLVM_DIR = $LlvmDirResolved
$env:LLVM_ROOT = $LlvmRootResolved
$env:VCPKG_ROOT = $VcpkgDir
$env:Path = "$LlvmRootResolved\bin;$env:Path"

Write-Log "Environment configured:"
Write-Log "  JOCKY_ROOT = $JockyRoot"
Write-Log "  LLVM_DIR   = $LlvmDirResolved"
Write-Log "  LLVM_ROOT  = $LlvmRootResolved"
Write-Log "  VCPKG_ROOT = $VcpkgDir"

if ($SkipCMake) {
    Write-Log "Skipping CMake configure (-SkipCMake)."
    Write-Log "Bootstrap finished. Dot-source `"$EnvFile`" in new shells to reload env vars."
    exit 0
}

$cmakeListsPath = Join-Path $JockyRoot "CMakeLists.txt"
if (-not (Test-Path $cmakeListsPath)) {
    Write-WarnLog "No CMakeLists.txt found at $JockyRoot -- skipping configure step."
    Write-WarnLog "Bootstrap finished (env only). Dot-source `"$EnvFile`" to load env vars."
    exit 0
}

Write-Log "Configuring project with CMake (build type: $CMakeBuildType)."
$vcpkgToolchain = Join-Path $VcpkgDir "scripts\buildsystems\vcpkg.cmake"

cmake -S $JockyRoot -B $JockyBuildDir `
    -DCMAKE_BUILD_TYPE=$CMakeBuildType `
    "-DLLVM_DIR=$LlvmDirResolved" `
    "-DCMAKE_TOOLCHAIN_FILE=$vcpkgToolchain"

Write-Log "CMake configure complete. Build directory: $JockyBuildDir"
Write-Log ""
Write-Log "Next steps:"
Write-Log "  . `"$EnvFile`" # load env vars into your current session"
Write-Log "  cmake --build `"$JockyBuildDir`""