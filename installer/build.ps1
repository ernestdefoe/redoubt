<#
.SYNOPSIS
    Build Redoubt.msi.

.DESCRIPTION
    Builds the three shipping binaries in release mode, stages them, and
    packages them with WiX.

    Staging is not busywork. The AMSI provider is loaded into every PowerShell,
    Office and .NET process on a machine where Redoubt is registered, so the
    DLL in the build directory is frequently locked and cargo cannot overwrite
    it. The packaging build therefore uses its own target directory, well away
    from whatever is running.

.PARAMETER SkipBuild
    Package whatever is already staged. Useful when iterating on the installer
    itself rather than on the code.

.EXAMPLE
    pwsh installer/build.ps1
#>
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [string]$Version
)

$ErrorActionPreference = 'Stop'

$InstallerDir = $PSScriptRoot
$RootDir = Split-Path -Parent $InstallerDir
$BrandDir = Join-Path $RootDir 'brand'
$StageDir = Join-Path $InstallerDir 'stage'
$OutDir = Join-Path $InstallerDir 'out'

# Its own target directory, so a locked DLL in the development build cannot
# stop a release from being packaged.
$PackTarget = Join-Path $env:USERPROFILE '.cargo-target\redoubt-pack'

if (-not $Version) {
    $cargoToml = Get-Content (Join-Path $RootDir 'Cargo.toml') -Raw
    if ($cargoToml -match '(?m)^version\s*=\s*"([^"]+)"') {
        $Version = $Matches[1]
    } else {
        throw 'Could not read the version from Cargo.toml; pass -Version.'
    }
}
Write-Host "Redoubt $Version" -ForegroundColor Cyan

# --- artwork ---------------------------------------------------------------

if (-not (Test-Path (Join-Path $BrandDir 'redoubt.ico'))) {
    Write-Host 'Generating brand assets...'
    & python (Join-Path $RootDir 'tools\brand.py') | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'brand.py failed' }
}

# --- build -----------------------------------------------------------------

if (-not $SkipBuild) {
    Write-Host 'Building release binaries...'
    Push-Location $RootDir
    try {
        $env:CARGO_TARGET_DIR = $PackTarget
        & cargo build --release -p redoubt-cli -p redoubt-service -p redoubt-amsi
        if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
    } finally {
        Remove-Item Env:\CARGO_TARGET_DIR -ErrorAction SilentlyContinue
        Pop-Location
    }
}

# --- stage -----------------------------------------------------------------

if (Test-Path $StageDir) { Remove-Item $StageDir -Recurse -Force }
New-Item -ItemType Directory -Path $StageDir -Force | Out-Null

$binaries = @('redoubt.exe', 'redoubtd.exe', 'redoubt_amsi.dll')
foreach ($b in $binaries) {
    $src = Join-Path "$PackTarget\release" $b
    if (-not (Test-Path $src)) { throw "missing build output: $src" }
    Copy-Item $src (Join-Path $StageDir $b) -Force
}

# Every shipping binary must carry its identity. An unsigned tool with no
# publisher in its properties is one nobody should grant administrator rights,
# and this is the cheap half of earning that.
foreach ($b in $binaries) {
    $info = (Get-Item (Join-Path $StageDir $b)).VersionInfo
    if (-not $info.CompanyName) { throw "$b has no version resource; run cargo clean and rebuild" }
    Write-Host ("  {0,-20} {1} {2}" -f $b, $info.ProductName, $info.FileVersion)
}

# --- package ---------------------------------------------------------------

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$msi = Join-Path $OutDir "Redoubt-$Version-x64.msi"

Write-Host 'Packaging...'
& wix build `
    (Join-Path $InstallerDir 'Redoubt.wxs') `
    -arch x64 `
    -ext WixToolset.UI.wixext `
    -ext WixToolset.Util.wixext `
    -d "Version=$Version" `
    -d "RootDir=$RootDir" `
    -d "BrandDir=$BrandDir" `
    -d "StageDir=$StageDir" `
    -d "InstallerDir=$InstallerDir" `
    -o $msi
if ($LASTEXITCODE -ne 0) { throw 'wix build failed' }

$size = [math]::Round((Get-Item $msi).Length / 1MB, 1)
Write-Host ""
Write-Host "  $msi  ($size MB)" -ForegroundColor Green
Write-Host ""
Write-Host "  Not code-signed. Windows SmartScreen will warn on first run until"
Write-Host "  it is signed with a certificate."
