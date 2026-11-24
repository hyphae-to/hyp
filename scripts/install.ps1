# Hyphae (`hyp`) Windows PowerShell Installer — https://hyphae.to
# Usage:
#   irm https://hyphae.to/install.ps1 | iex
#   .\install.ps1 -Version v0.2.0 -InstallDir "$env:LOCALAPPDATA\Programs\hyphae\bin"

[CmdletBinding()]
param(
    [string]$Version = $env:HYPHAE_VERSION,
    [string]$InstallDir = $env:HYPHAE_INSTALL_DIR,
    [string]$BaseUrl = $env:HYPHAE_BASE_URL,
    [switch]$DryRun,
    [switch]$Yes,
    [switch]$Force,
    [switch]$NoOnboard
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Ensure TLS 1.2 is enabled on Windows PowerShell 5.1.
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # Ignore on newer .NET runtimes that manage TLS automatically.
}

$Repo = "hyphae-to/hyp"
$SkipOnboard = $NoOnboard.IsPresent -or (-not [string]::IsNullOrWhiteSpace($env:HYPHAE_NO_ONBOARD))

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $LocalAppData = $env:LOCALAPPDATA
    if ([string]::IsNullOrWhiteSpace($LocalAppData)) {
        $LocalAppData = Join-Path $HOME "AppData\Local"
    }
    $InstallDir = Join-Path $LocalAppData "Programs\hyphae\bin"
}

function Test-HyphaeConfigured {
    $cfgDir = $env:HYPHAE_CONFIG_DIR
    if ([string]::IsNullOrWhiteSpace($cfgDir)) {
        if (-not [string]::IsNullOrWhiteSpace($env:XDG_CONFIG_HOME)) {
            $cfgDir = Join-Path $env:XDG_CONFIG_HOME "hyphae"
        } else {
            $cfgDir = Join-Path (Join-Path $HOME ".config") "hyphae"
        }
    }
    return (Test-Path -LiteralPath (Join-Path $cfgDir "node.json")) -or (Test-Path -LiteralPath (Join-Path $cfgDir "connector.json"))
}

function Test-InteractiveTty {
    if ($Yes -or $DryRun -or (-not [string]::IsNullOrWhiteSpace($env:CI))) {
        return $false
    }
    try {
        return [Environment]::UserInteractive -and (-not [Console]::IsOutputRedirected) -and (-not [Console]::IsInputRedirected)
    } catch {
        return $false
    }
}

function Write-NextSteps {
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  hyp deploy providers   # list one-click self-hosting targets"
    Write-Host "  hyp pair guide         # pair laptops, servers, and agents"
    Write-Host "  hyp onboard            # interactive mesh setup"
}

function Resolve-Target {
    $arch = $null
    try {
        $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    } catch {
        $arch = $env:PROCESSOR_ARCHITECTURE
    }

    switch ($arch.ToUpperInvariant()) {
        "X64" { return "x86_64-pc-windows-msvc" }
        "AMD64" { return "x86_64-pc-windows-msvc" }
        default {
            throw "Unsupported Windows architecture '$arch'. Supported: x86_64 (AMD64)."
        }
    }
}

function Normalize-And-Validate-Version([string]$Raw) {
    $v = $Raw.Trim()
    if ($v -match '^[0-9]') {
        $v = "v$v"
    }
    if ([string]::IsNullOrWhiteSpace($v) -or $v -match '\.\.' -or $v -notmatch '^v[0-9A-Za-z._+-]+$') {
        throw "Invalid version tag '$Raw'. Expected format like v0.2.0."
    }
    return $v
}

function Resolve-LatestVersion {
    $apiUrl = "https://api.github.com/repos/$Repo/releases/latest"
    $headers = @{
        "Accept"     = "application/vnd.github+json"
        "User-Agent" = "hyphae-installer"
    }
    $resp = Invoke-RestMethod -Uri $apiUrl -Headers $headers -UseBasicParsing
    if (-not $resp -or [string]::IsNullOrWhiteSpace($resp.tag_name)) {
        throw "Could not resolve latest release tag from $apiUrl (pass -Version <tag>)."
    }
    return Normalize-And-Validate-Version $resp.tag_name
}

function Find-ExpectedSha256([string]$SumsPath, [string]$ArchiveName) {
    foreach ($line in Get-Content -Path $SumsPath) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }
        if ($trimmed -match '^([0-9a-fA-F]{64})\s+\*?(\./)?(.+)$') {
            $hash = $Matches[1].ToLowerInvariant()
            $file = $Matches[3].Trim()
            if ($file -eq $ArchiveName) {
                return $hash
            }
        }
    }
    return $null
}

function Ensure-UserPathContains([string]$Dir) {
    $normalizedTarget = $Dir.TrimEnd('\')
    $currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $entries = @()
    if (-not [string]::IsNullOrWhiteSpace($currentUserPath)) {
        $entries = $currentUserPath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    }

    $alreadyPresent = $false
    foreach ($entry in $entries) {
        if ($entry.TrimEnd('\').Equals($normalizedTarget, [System.StringComparison]::OrdinalIgnoreCase)) {
            $alreadyPresent = $true
            break
        }
    }

    if (-not $alreadyPresent) {
        $newEntries = @($entries + $Dir)
        $newUserPath = $newEntries -join ';'
        [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
        Write-Host "Added $Dir to User PATH (restart your terminal if needed)."
    }

    # Also update current session PATH so `hyp` works immediately.
    $sessionEntries = @()
    if (-not [string]::IsNullOrWhiteSpace($env:Path)) {
        $sessionEntries = $env:Path -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    }
    $inSession = $false
    foreach ($entry in $sessionEntries) {
        if ($entry.TrimEnd('\').Equals($normalizedTarget, [System.StringComparison]::OrdinalIgnoreCase)) {
            $inSession = $true
            break
        }
    }
    if (-not $inSession) {
        $env:Path = if ([string]::IsNullOrWhiteSpace($env:Path)) { $Dir } else { "$Dir;$env:Path" }
    }
}

$Target = Resolve-Target

if (-not [string]::IsNullOrWhiteSpace($Version)) {
    $Version = Normalize-And-Validate-Version $Version
} else {
    if (-not [string]::IsNullOrWhiteSpace($BaseUrl)) {
        throw "-Version <tag> is required when using -BaseUrl."
    }
    $Version = Resolve-LatestVersion
}

$ArchiveName = "hyp-$Version-$Target.zip"
if (-not [string]::IsNullOrWhiteSpace($BaseUrl)) {
    $BaseTrimmed = $BaseUrl.TrimEnd('/')
    $ArchiveUrl = "$BaseTrimmed/$ArchiveName"
    $SumsUrl = "$BaseTrimmed/SHA256SUMS.txt"
} else {
    $ReleaseBase = "https://github.com/$Repo/releases/download/$Version"
    $ArchiveUrl = "$ReleaseBase/$ArchiveName"
    $SumsUrl = "$ReleaseBase/SHA256SUMS.txt"
}

$BinPath = Join-Path $InstallDir "hyp.exe"

if ($DryRun) {
    Write-Host "Hyphae installer dry-run:"
    Write-Host "  Version:      $Version"
    Write-Host "  Target:       $Target"
    Write-Host "  Archive URL:  $ArchiveUrl"
    Write-Host "  Checksums:    $SumsUrl"
    Write-Host "  Install path: $BinPath"
    return
}

# Inspect existing installation before downloading so updates and same-version runs behave gracefully.
$WasInstalled = Test-Path -LiteralPath $BinPath
$ExistingVer = ""
if ($WasInstalled) {
    try {
        $verLine = (& $BinPath version 2>$null | Select-Object -First 1)
        if ($verLine -and ($verLine -match 'hyphae\s+v?(\S+)')) {
            $ExistingVer = $Matches[1].Trim()
        }
    } catch {
        $ExistingVer = ""
    }
}
$TargetVer = $Version.TrimStart('v')
$IsInteractive = Test-InteractiveTty
$IsConfigured = Test-HyphaeConfigured

if ($WasInstalled -and (-not [string]::IsNullOrWhiteSpace($ExistingVer)) -and ($ExistingVer -eq $TargetVer)) {
    if ($IsInteractive -and (-not $Force)) {
        Write-Host "Hyphae $Version is already installed and up to date at $BinPath."
        if ((-not $IsConfigured) -and (-not $SkipOnboard)) {
            $reply = Read-Host "Hyphae is not configured yet. Start interactive onboarding wizard? [Y/n]"
            if ([string]::IsNullOrWhiteSpace($reply) -or $reply -match '^(y|yes)$') {
                Write-Host ""
                Write-Host "Starting Hyphae interactive setup wizard..."
                & $BinPath onboard
                return
            }
            Write-NextSteps
            return
        } elseif ($IsConfigured) {
            $reply = Read-Host "Open setup/config wizard (w), run doctor (d), reinstall anyway (r), or exit (N)? [w/d/r/N]"
            switch -Regex ($reply.Trim()) {
                '^(w)$' {
                    Write-Host ""
                    Write-Host "Starting Hyphae interactive setup wizard..."
                    & $BinPath onboard
                    return
                }
                '^(d)$' {
                    & $BinPath doctor
                    return
                }
                '^(r)$' {
                    # Proceed with full SHA-256-verified reinstall.
                }
                default {
                    return
                }
            }
        } else {
            Write-NextSteps
            return
        }
    }
} elseif ($WasInstalled -and (-not [string]::IsNullOrWhiteSpace($ExistingVer)) -and ($ExistingVer -ne $TargetVer)) {
    if ($IsInteractive -and (-not $Force)) {
        Write-Host "Hyphae v$ExistingVer is already installed at $BinPath."
        $reply = Read-Host "Update to $Version? [Y/n]"
        if ((-not [string]::IsNullOrWhiteSpace($reply)) -and ($reply -notmatch '^(y|yes)$')) {
            Write-Host "Update cancelled."
            return
        }
    }
}

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("hyphae-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null

try {
    $ArchivePath = Join-Path $TmpDir $ArchiveName
    $SumsPath = Join-Path $TmpDir "SHA256SUMS.txt"
    $ExtractDir = Join-Path $TmpDir "extract"
    $Headers = @{ "User-Agent" = "hyphae-installer" }

    Write-Host "Installing Hyphae $Version ($Target)..."
    Invoke-WebRequest -Uri $ArchiveUrl -OutFile $ArchivePath -Headers $Headers -UseBasicParsing
    Invoke-WebRequest -Uri $SumsUrl -OutFile $SumsPath -Headers $Headers -UseBasicParsing

    $ExpectedHash = Find-ExpectedSha256 -SumsPath $SumsPath -ArchiveName $ArchiveName
    if ([string]::IsNullOrWhiteSpace($ExpectedHash)) {
        throw "Checksum for '$ArchiveName' not found in SHA256SUMS.txt; aborting fail-closed."
    }

    $ActualHash = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualHash -ne $ExpectedHash) {
        throw "SHA-256 checksum mismatch for '$ArchiveName'! Expected $ExpectedHash, got $ActualHash; refusing to install."
    }
    Write-Host "Verified SHA-256 checksum ($ActualHash)."

    Expand-Archive -Path $ArchivePath -DestinationPath $ExtractDir -Force

    $SourceBin = Join-Path $ExtractDir "hyp.exe"
    if (-not (Test-Path -LiteralPath $SourceBin)) {
        $AltBin = Join-Path $ExtractDir "hyp-rs.exe"
        if (Test-Path -LiteralPath $AltBin) {
            $SourceBin = $AltBin
        } else {
            throw "Archive '$ArchiveName' did not contain expected 'hyp.exe' binary."
        }
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $StagedBin = Join-Path $InstallDir (".hyp.tmp." + [System.Guid]::NewGuid().ToString("N") + ".exe")
    Copy-Item -LiteralPath $SourceBin -Destination $StagedBin -Force
    Move-Item -LiteralPath $StagedBin -Destination $BinPath -Force

    Ensure-UserPathContains -Dir $InstallDir

    $IsUpdate = $WasInstalled -and (-not [string]::IsNullOrWhiteSpace($ExistingVer)) -and ($ExistingVer -ne $TargetVer)
    if ($IsUpdate) {
        Write-Host "Updated hyp v$ExistingVer -> $Version at $BinPath"
    } else {
        Write-Host "Installed hyp to $BinPath"
    }
    & $BinPath version

    if ($IsUpdate -and $IsConfigured) {
        try {
            & $BinPath onboard --install-skill 2>$null | Out-Null
        } catch {
            # Best-effort skill refresh on update.
        }
        if ($IsInteractive) {
            Write-Host ""
            Write-Host "Running post-update health check..."
            try {
                & $BinPath doctor
            } catch {
                # Non-fatal post-update diagnostic check.
            }
            Write-Host ""
            Write-Host "Tip: Restart any running 'hyp daemon' process so the updated binary takes effect."
        } else {
            Write-NextSteps
        }
    } elseif ((-not $IsConfigured) -and (-not $SkipOnboard) -and $IsInteractive) {
        Write-Host ""
        Write-Host "Starting Hyphae interactive setup wizard..."
        & $BinPath onboard
    } else {
        Write-NextSteps
    }
} finally {
    if (Test-Path -LiteralPath $TmpDir) {
        Remove-Item -LiteralPath $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
