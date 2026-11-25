# Hyphae (`hyp`) Windows PowerShell Uninstaller - https://hyphae.to
#
# Usage:
#   irm https://hyphae.to/uninstall.ps1 | iex
#   .\uninstall.ps1 [-DryRun] [-Yes] [-KeepBinary] [-KeepState] [-KeepHarnesses] [-InstallDir <path>] [-StateDir <path>] [-Help]
#
# Safely stops and removes the HyphaeDaemon Task Scheduler service and user-owned
# `hyp.exe` daemon processes, restores any chained Claude Code / Antigravity
# statusLines BEFORE removing state, surgically removes Hyphae MCP entries and
# hook commands from detected Windows harness configs (preserving all non-Hyphae
# entries), cleans standalone Hyphae plugins/commands/skills/Herdr mods, removes
# Hyphae state directories, removes `hyp.exe` binaries and empty install folder,
# and strips the Hyphae bin directory from the User PATH environment variable.

[CmdletBinding()]
param(
    [Alias("n")]
    [switch]$DryRun,
    [Alias("y")]
    [switch]$Yes,
    [switch]$KeepBinary,
    [switch]$KeepState,
    [switch]$KeepHarnesses,
    [string]$InstallDir = "",
    [string]$StateDir = "",
    [Alias("h")]
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Show-Usage {
    @'
Hyphae (`hyp`) Windows PowerShell uninstaller

Usage:
  uninstall.ps1 [OPTIONS]

Options:
  -DryRun, -n             Print complete removal/restore plan without modifying anything
  -Yes, -y                Skip interactive confirmation prompt
  -KeepBinary             Keep installed `hyp.exe` binary and User PATH entry
  -KeepState              Keep Hyphae state directories, keys, and database
  -KeepHarnesses          Leave harness configs, skills, slash commands, and statusLines untouched
  -InstallDir <path>      Override binary directory (default: %LOCALAPPDATA%\Programs\hyphae\bin)
  -StateDir <path>        Override Hyphae state directory to remove
  -Help, -h               Show this help message

Environment overrides:
  HYPHAE_INSTALL_DIR      Default binary directory if -InstallDir is omitted
  HYPHAE_STATE_DIR        Additional/override state directory if -StateDir is omitted
  HYPHAE_CONFIG_DIR       Additional/override config directory
  CLAUDE_CONFIG_DIR       Optional Claude Code profile directory to also clean
  HERDR_APP_HOME          Optional Herdr desktop app directory
'@ | Write-Output
}

if ($Help) {
    Show-Usage
    return
}

# ---------------------------------------------------------------------------
# Path normalization & strict path safety guards
# ---------------------------------------------------------------------------

function Get-NormalizedPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ""
    }
    try {
        $full = [System.IO.Path]::GetFullPath($Path.Trim())
        $root = [System.IO.Path]::GetPathRoot($full)
        if (-not [string]::IsNullOrEmpty($root) -and $full.Equals($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $full
        }
        return $full.TrimEnd('\', '/')
    } catch {
        return ""
    }
}

function Test-PathEquals {
    param([string]$Left, [string]$Right)
    $a = Get-NormalizedPath $Left
    $b = Get-NormalizedPath $Right
    if ([string]::IsNullOrEmpty($a) -or [string]::IsNullOrEmpty($b)) {
        return $false
    }
    return $a.Equals($b, [System.StringComparison]::OrdinalIgnoreCase)
}

function Add-UniquePath {
    param(
        [System.Collections.Generic.List[string]]$List,
        [System.Collections.Generic.HashSet[string]]$Seen,
        [string]$Path
    )
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }
    $norm = Get-NormalizedPath $Path
    if ([string]::IsNullOrEmpty($norm)) {
        return
    }
    if ($Seen.Add($norm)) {
        $List.Add($Path)
    }
}

function Test-InteractiveTty {
    if (-not [string]::IsNullOrWhiteSpace($env:CI)) {
        return $false
    }
    try {
        return [Environment]::UserInteractive -and (-not [Console]::IsInputRedirected) -and (-not [Console]::IsOutputRedirected)
    } catch {
        return $false
    }
}

# Resolve base user directories.
$UserHome = $env:USERPROFILE
if ([string]::IsNullOrWhiteSpace($UserHome)) {
    $UserHome = $HOME
}
if ([string]::IsNullOrWhiteSpace($UserHome)) {
    $UserHome = [Environment]::GetFolderPath("UserProfile")
}

$RealProfile = ""
try {
    $RealProfile = [Environment]::GetFolderPath("UserProfile")
} catch {
    $RealProfile = $UserHome
}
$IsRealProfile = (-not [string]::IsNullOrWhiteSpace($RealProfile)) -and (Test-PathEquals $UserHome $RealProfile)

$LocalAppData = $env:LOCALAPPDATA
if ([string]::IsNullOrWhiteSpace($LocalAppData)) {
    $LocalAppData = Join-Path $UserHome "AppData\Local"
}

$AppData = $env:APPDATA
if ([string]::IsNullOrWhiteSpace($AppData)) {
    $AppData = Join-Path $UserHome "AppData\Roaming"
}

$ConfigHome = $env:XDG_CONFIG_HOME
if ([string]::IsNullOrWhiteSpace($ConfigHome)) {
    $ConfigHome = Join-Path $UserHome ".config"
}

$HerdrAppDir = $env:HERDR_APP_HOME
if ([string]::IsNullOrWhiteSpace($HerdrAppDir)) {
    $HerdrAppDir = Join-Path $ConfigHome "herdr-app"
}

$ExplicitInstallDir = -not [string]::IsNullOrWhiteSpace($InstallDir)
if (-not $ExplicitInstallDir) {
    if (-not [string]::IsNullOrWhiteSpace($env:HYPHAE_INSTALL_DIR)) {
        $InstallDir = $env:HYPHAE_INSTALL_DIR
    } else {
        $InstallDir = Join-Path $LocalAppData "Programs\hyphae\bin"
    }
}
$DefaultInstallDir = Join-Path $LocalAppData "Programs\hyphae\bin"
$ExplicitStateDir = -not [string]::IsNullOrWhiteSpace($StateDir)

# Build strict forbidden-path set so Remove-Item -Recurse -Force can NEVER hit root, $HOME, or OS dirs.
$ProtectedPathSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($rawProtected in @(
    $HOME,
    $env:USERPROFILE,
    $UserHome,
    $RealProfile,
    $AppData,
    $LocalAppData,
    (Join-Path $LocalAppData "Programs"),
    (Join-Path $UserHome "AppData"),
    (Join-Path $UserHome ".config"),
    $ConfigHome,
    $env:XDG_CONFIG_HOME,
    $env:SystemRoot,
    $env:WINDIR,
    $env:ProgramFiles,
    ${env:ProgramFiles(x86)},
    $env:ProgramData
)) {
    $norm = Get-NormalizedPath $rawProtected
    if (-not [string]::IsNullOrEmpty($norm)) {
        [void]$ProtectedPathSet.Add($norm)
    }
}
foreach ($homeCandidate in @($HOME, $UserHome, $RealProfile)) {
    $normHome = Get-NormalizedPath $homeCandidate
    if (-not [string]::IsNullOrEmpty($normHome)) {
        try {
            $parentOfHome = [System.IO.Path]::GetDirectoryName($normHome)
            if (-not [string]::IsNullOrEmpty($parentOfHome)) {
                [void]$ProtectedPathSet.Add((Get-NormalizedPath $parentOfHome))
            }
        } catch {
            # Ignore invalid parent lookups.
        }
    }
}

function Test-SafeRemovalPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }
    $trimmed = $Path.Trim()
    if ($trimmed -eq "." -or $trimmed -eq ".." -or $trimmed -match '^[/\\]+$' -or $trimmed -match '^[A-Za-z]:[/\\]*$') {
        return $false
    }
    $norm = Get-NormalizedPath $trimmed
    if ([string]::IsNullOrEmpty($norm)) {
        return $false
    }
    try {
        $root = [System.IO.Path]::GetPathRoot($norm)
        if (-not [string]::IsNullOrEmpty($root) -and $norm.Equals($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
    } catch {
        return $false
    }
    if ($norm -match '^[A-Za-z]:$' -or $norm -match '^[/\\]+$') {
        return $false
    }
    if ($ProtectedPathSet.Contains($norm)) {
        return $false
    }
    return $true
}

function Assert-SafeRemovalPath {
    param(
        [string]$Path,
        [string]$Context = "path"
    )
    if (-not (Test-SafeRemovalPath $Path)) {
        throw "Refusing unsafe removal of ${Context} '${Path}' (empty, root, home, or protected system directory)."
    }
}

function Remove-PathSafely {
    param(
        [string]$Path,
        [switch]$Recurse
    )
    Assert-SafeRemovalPath -Path $Path -Context "target"
    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $isReparsePoint = (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    if ($isReparsePoint) {
        # Never recurse through junctions or symlinks.
        if ($item.PSIsContainer) {
            [System.IO.Directory]::Delete($item.FullName, $false)
        } else {
            Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
        }
        return $true
    }
    if ($Recurse -and $item.PSIsContainer) {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
    } else {
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
    return $true
}

# Validate explicit -StateDir early (fail-closed if caller passed root/$HOME/protected dir).
if ($ExplicitStateDir -and (-not $KeepState) -and (-not (Test-SafeRemovalPath $StateDir))) {
    [Console]::Error.WriteLine("error: refusing unsafe -StateDir '${StateDir}' (empty, root, home, or protected directory)")
    exit 2
}

# Optional extra Claude Code profile directory via CLAUDE_CONFIG_DIR (hermetic under isolated USERPROFILE).
$ClaudeProfileDir = ""
if (-not [string]::IsNullOrWhiteSpace($env:CLAUDE_CONFIG_DIR)) {
    $ccdRaw = $env:CLAUDE_CONFIG_DIR.Trim()
    if (Test-Path -LiteralPath $ccdRaw -PathType Container) {
        $ccdNorm = Get-NormalizedPath $ccdRaw
        $homeNorm = Get-NormalizedPath $UserHome
        $defaultClaudeNorm = Get-NormalizedPath (Join-Path $UserHome ".claude")
        $ccdAllow = $false
        if ($IsRealProfile) {
            $ccdAllow = $true
        } elseif ((-not [string]::IsNullOrEmpty($ccdNorm)) -and (-not [string]::IsNullOrEmpty($homeNorm))) {
            if ($ccdNorm.StartsWith(($homeNorm + "\"), [System.StringComparison]::OrdinalIgnoreCase) -or
                $ccdNorm.StartsWith(($homeNorm + "/"), [System.StringComparison]::OrdinalIgnoreCase)) {
                $ccdAllow = $true
            }
        }
        if ($ccdAllow -and (-not [string]::IsNullOrEmpty($ccdNorm)) -and
            (-not $ccdNorm.Equals($defaultClaudeNorm, [System.StringComparison]::OrdinalIgnoreCase)) -and
            (-not $ccdNorm.Equals($homeNorm, [System.StringComparison]::OrdinalIgnoreCase))) {
            $ClaudeProfileDir = $ccdRaw
        }
    }
}

# ---------------------------------------------------------------------------
# Process, Task Scheduler & User PATH helpers
# ---------------------------------------------------------------------------

function Invoke-ExternalQuiet {
    param(
        [string]$Executable,
        [string[]]$Arguments
    )
    $cmd = Get-Command $Executable -ErrorAction SilentlyContinue
    if (-not $cmd) {
        return -1
    }
    $prevEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $global:LASTEXITCODE = 0
        $null = & $cmd.Source @Arguments 2>$null
        return [int]$LASTEXITCODE
    } catch {
        return -1
    } finally {
        $ErrorActionPreference = $prevEap
    }
}

function Test-ScheduledTaskExists {
    param([string]$TaskName)
    $rc = Invoke-ExternalQuiet -Executable "schtasks.exe" -Arguments @("/Query", "/TN", $TaskName)
    return ($rc -eq 0)
}

function Find-HyphaeDaemonProcesses {
    $found = New-Object System.Collections.Generic.List[object]
    if (-not $IsRealProfile) {
        return ,$found
    }
    $currentUser = [Environment]::UserName
    $procs = $null
    try {
        if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
            $procs = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'hyp.exe' OR Name = 'hyp-rs.exe'" -ErrorAction SilentlyContinue
        } elseif (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
            $procs = Get-WmiObject -Class Win32_Process -Filter "Name = 'hyp.exe' OR Name = 'hyp-rs.exe'" -ErrorAction SilentlyContinue
        }
    } catch {
        return ,$found
    }

    if ($null -eq $procs) {
        return ,$found
    }

    foreach ($proc in @($procs)) {
        if ($null -eq $proc) {
            continue
        }
        $procId = 0
        try {
            $procId = [int]$proc.ProcessId
        } catch {
            continue
        }
        if ($procId -le 0 -or $procId -eq $PID) {
            continue
        }

        # Verify current-user ownership before targeting any process.
        $procOwner = ""
        try {
            if ($proc.PSObject.TypeNames -contains 'Microsoft.Management.Infrastructure.CimInstance') {
                $ownerInfo = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction SilentlyContinue
                if ($null -ne $ownerInfo -and $ownerInfo.ReturnValue -eq 0) {
                    $procOwner = [string]$ownerInfo.User
                }
            } else {
                $ownerInfo = $proc.GetOwner()
                if ($null -ne $ownerInfo -and $ownerInfo.ReturnValue -eq 0) {
                    $procOwner = [string]$ownerInfo.User
                }
            }
        } catch {
            $procOwner = ""
        }
        if ([string]::IsNullOrWhiteSpace($procOwner) -or (-not $procOwner.Equals($currentUser, [System.StringComparison]::OrdinalIgnoreCase))) {
            continue
        }

        $cmdLine = ""
        try {
            if ($null -ne $proc.CommandLine) {
                $cmdLine = [string]$proc.CommandLine
            }
        } catch {
            $cmdLine = ""
        }
        if ($cmdLine -match '(?i)(^|[\s"\\/])(hyp|hyp-rs)(\.exe)?["'']?\s+(daemon|node\s+start)(\s|$)') {
            $found.Add([PSCustomObject]@{
                Pid         = $procId
                CommandLine = $cmdLine.Trim()
            })
        }
    }
    return ,$found
}

function Test-UserPathContains {
    param([string]$Dir)
    $normalizedTarget = Get-NormalizedPath $Dir
    if ([string]::IsNullOrEmpty($normalizedTarget)) {
        return $false
    }
    $currentUserPath = ""
    try {
        $currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    } catch {
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($currentUserPath)) {
        return $false
    }
    foreach ($entry in ($currentUserPath -split ';')) {
        if ([string]::IsNullOrWhiteSpace($entry)) {
            continue
        }
        $normEntry = Get-NormalizedPath $entry
        if ((-not [string]::IsNullOrEmpty($normEntry)) -and $normEntry.Equals($normalizedTarget, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
        if ($entry.Trim().TrimEnd('\', '/').Equals($Dir.Trim().TrimEnd('\', '/'), [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Remove-FromUserPath {
    param([string]$Dir)
    $normalizedTarget = Get-NormalizedPath $Dir
    $rawTrimmed = $Dir.Trim().TrimEnd('\', '/')
    if ([string]::IsNullOrEmpty($normalizedTarget) -and [string]::IsNullOrEmpty($rawTrimmed)) {
        return $false
    }

    $removed = $false
    $currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not [string]::IsNullOrWhiteSpace($currentUserPath)) {
        $kept = New-Object System.Collections.Generic.List[string]
        foreach ($entry in ($currentUserPath -split ';')) {
            if ([string]::IsNullOrWhiteSpace($entry)) {
                continue
            }
            $normEntry = Get-NormalizedPath $entry
            $isMatch = $false
            if ((-not [string]::IsNullOrEmpty($normEntry)) -and (-not [string]::IsNullOrEmpty($normalizedTarget)) -and
                $normEntry.Equals($normalizedTarget, [System.StringComparison]::OrdinalIgnoreCase)) {
                $isMatch = $true
            } elseif ($entry.Trim().TrimEnd('\', '/').Equals($rawTrimmed, [System.StringComparison]::OrdinalIgnoreCase)) {
                $isMatch = $true
            }
            if ($isMatch) {
                $removed = $true
                continue
            }
            $kept.Add($entry)
        }
        if ($removed) {
            $newUserPath = ($kept.ToArray()) -join ';'
            [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
        }
    }

    # Also update current session PATH without touching unrelated entries.
    if (-not [string]::IsNullOrWhiteSpace($env:Path)) {
        $keptSession = New-Object System.Collections.Generic.List[string]
        $sessionChanged = $false
        foreach ($entry in ($env:Path -split ';')) {
            if ([string]::IsNullOrWhiteSpace($entry)) {
                continue
            }
            $normEntry = Get-NormalizedPath $entry
            $isMatch = $false
            if ((-not [string]::IsNullOrEmpty($normEntry)) -and (-not [string]::IsNullOrEmpty($normalizedTarget)) -and
                $normEntry.Equals($normalizedTarget, [System.StringComparison]::OrdinalIgnoreCase)) {
                $isMatch = $true
            } elseif ($entry.Trim().TrimEnd('\', '/').Equals($rawTrimmed, [System.StringComparison]::OrdinalIgnoreCase)) {
                $isMatch = $true
            }
            if ($isMatch) {
                $sessionChanged = $true
                continue
            }
            $keptSession.Add($entry)
        }
        if ($sessionChanged) {
            $env:Path = ($keptSession.ToArray()) -join ';'
        }
    }

    return $removed
}

# ---------------------------------------------------------------------------
# Surgical JSON / TOML / StatusLine cleaner (PS 5.1 & PowerShell 7+ native)
# ---------------------------------------------------------------------------

$HyphaeHookNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
[void]$HyphaeHookNames.Add("hyphae-before-tool")
[void]$HyphaeHookNames.Add("hyphae-after-tool")
[void]$HyphaeHookNames.Add("hyphae-after-agent")

$HyphaeHookRegex = '(?i)(?:^|[\s/\\"''])(?:hyp|hyp-rs)(?:\.exe)?["'']?\s+hook\s+(?:claude|codex|cursor|gemini|antigravity|opencode|herdr|t3|openclaw)\b|hyphae\.mjs\s+hook\b|\bhyphae-hook\b|agents-mesh[^\r\n]*\bhook\b'

function Test-JsonObject {
    param($Value)
    return ($null -ne $Value) -and ($Value -is [System.Management.Automation.PSCustomObject])
}

function Test-JsonProperty {
    param($Obj, [string]$Name)
    if (-not (Test-JsonObject $Obj)) {
        return $false
    }
    return ($null -ne $Obj.PSObject.Properties[$Name])
}

function Get-JsonPropertyCount {
    param($Obj)
    if (-not (Test-JsonObject $Obj)) {
        return 0
    }
    return ($Obj.PSObject.Properties | Measure-Object).Count
}

function Write-AtomicUtf8Text {
    param(
        [string]$Path,
        [string]$Content
    )
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $parent = [System.IO.Path]::GetDirectoryName($fullPath)
    $tmpPath = Join-Path $parent (".hyp-uninstall-" + [System.Guid]::NewGuid().ToString("N") + ".tmp")
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    try {
        [System.IO.File]::WriteAllText($tmpPath, $Content, $utf8NoBom)
        Move-Item -LiteralPath $tmpPath -Destination $fullPath -Force
    } catch {
        if (Test-Path -LiteralPath $tmpPath) {
            Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}

function Read-JsonObject {
    param(
        [string]$Path,
        [System.Collections.Generic.List[string]]$Warnings
    )
    try {
        $raw = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
        if ([string]::IsNullOrWhiteSpace($raw)) {
            $Warnings.Add("${Path}: skipped empty JSON file")
            return $null
        }
        $parsed = $raw | ConvertFrom-Json
    } catch {
        $Warnings.Add("${Path}: skipped invalid JSON ($($_.Exception.Message))")
        return $null
    }
    if (-not (Test-JsonObject $parsed)) {
        $Warnings.Add("${Path}: skipped non-object JSON root")
        return $null
    }
    return $parsed
}

function Save-JsonObject {
    param(
        [string]$Path,
        $Doc
    )
    $rendered = ($Doc | ConvertTo-Json -Depth 32) + "`n"
    Write-AtomicUtf8Text -Path $Path -Content $rendered
}

function Split-CommandWords {
    param([string]$Cmd)
    $words = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($Cmd)) {
        return ,$words
    }
    $sb = New-Object System.Text.StringBuilder
    $inWord = $false
    $inSingle = $false
    $inDouble = $false
    $len = $Cmd.Length
    for ($i = 0; $i -lt $len; $i++) {
        $ch = $Cmd[$i]
        if ($inSingle) {
            if ($ch -eq "'") {
                $inSingle = $false
            } else {
                [void]$sb.Append($ch)
            }
            continue
        }
        if ($inDouble) {
            if ($ch -eq '"') {
                if (($i + 1) -lt $len -and $Cmd[$i + 1] -eq '"') {
                    [void]$sb.Append('"')
                    $i++
                } else {
                    $inDouble = $false
                }
            } elseif ($ch -eq '\' -and ($i + 1) -lt $len -and $Cmd[$i + 1] -eq '"') {
                [void]$sb.Append('"')
                $i++
            } else {
                [void]$sb.Append($ch)
            }
            continue
        }
        if ($ch -eq "'") {
            $inSingle = $true
            $inWord = $true
            continue
        }
        if ($ch -eq '"') {
            $inDouble = $true
            $inWord = $true
            continue
        }
        if ([char]::IsWhiteSpace($ch)) {
            if ($inWord) {
                $words.Add($sb.ToString())
                [void]$sb.Clear()
                $inWord = $false
            }
            continue
        }
        [void]$sb.Append($ch)
        $inWord = $true
    }
    if ($inWord) {
        $words.Add($sb.ToString())
    }
    return ,$words
}

function Test-HyphaeStatusLineCommand {
    param([string]$Cmd)
    if ([string]::IsNullOrWhiteSpace($Cmd)) {
        return $false
    }
    $words = Split-CommandWords $Cmd
    if ($words.Count -lt 2 -or $words[1] -ne "statusline") {
        return $false
    }
    $binName = [System.IO.Path]::GetFileName($words[0]).ToLowerInvariant()
    if ($binName -in @("hyp", "hyp.exe", "hyp-rs", "hyp-rs.exe")) {
        return $true
    }
    foreach ($w in $words) {
        if ($w -eq "--harness" -or $w.StartsWith("--harness=")) {
            return $true
        }
    }
    return $false
}

function Get-ChainFileFromCommand {
    param([string]$Cmd)
    if ([string]::IsNullOrWhiteSpace($Cmd)) {
        return ""
    }
    $words = Split-CommandWords $Cmd
    for ($i = 0; $i -lt $words.Count; $i++) {
        $w = $words[$i]
        if ($w -eq "--chain-file") {
            if (($i + 1) -lt $words.Count -and (-not [string]::IsNullOrWhiteSpace($words[$i + 1]))) {
                return $words[$i + 1]
            }
            return ""
        }
        if ($w.StartsWith("--chain-file=")) {
            $rest = $w.Substring("--chain-file=".Length)
            if (-not [string]::IsNullOrWhiteSpace($rest)) {
                return $rest
            }
            return ""
        }
    }
    return ""
}

function Find-StatusLineChainBackup {
    param(
        [string]$Harness,
        [string]$Cmd,
        [string[]]$SearchDirs
    )
    $fileName = "${Harness}-statusline-chain.json"
    $candidates = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    $refPath = Get-ChainFileFromCommand $Cmd
    if (-not [string]::IsNullOrWhiteSpace($refPath)) {
        Add-UniquePath -List $candidates -Seen $seen -Path $refPath
    }
    foreach ($dir in $SearchDirs) {
        if (-not [string]::IsNullOrWhiteSpace($dir)) {
            Add-UniquePath -List $candidates -Seen $seen -Path (Join-Path $dir $fileName)
        }
    }

    foreach ($cand in $candidates) {
        if (Test-Path -LiteralPath $cand -PathType Leaf) {
            try {
                $raw = [System.IO.File]::ReadAllText($cand, [System.Text.Encoding]::UTF8)
                $parsed = $raw | ConvertFrom-Json
                if ($null -ne $parsed) {
                    return [PSCustomObject]@{
                        Path  = $cand
                        Value = $parsed
                    }
                }
            } catch {
                continue
            }
        }
    }
    return $null
}

function Test-HyphaeHookCommand {
    param([string]$Cmd)
    if ([string]::IsNullOrWhiteSpace($Cmd)) {
        return $false
    }
    $words = Split-CommandWords $Cmd
    if ($words.Count -ge 2) {
        $binName = [System.IO.Path]::GetFileName($words[0]).ToLowerInvariant()
        if (($binName -in @("hyp", "hyp.exe", "hyp-rs", "hyp-rs.exe")) -and $words[1] -eq "hook") {
            return $true
        }
    }
    return ($Cmd -match $HyphaeHookRegex)
}

function Test-HyphaeHookLeaf {
    param($Entry)
    if (-not (Test-JsonObject $Entry)) {
        return $false
    }
    if (Test-JsonProperty $Entry "command") {
        $cmdVal = $Entry.PSObject.Properties["command"].Value
        if (($cmdVal -is [string]) -and (Test-HyphaeHookCommand $cmdVal)) {
            return $true
        }
    }
    if (Test-JsonProperty $Entry "name") {
        $nameVal = $Entry.PSObject.Properties["name"].Value
        if (($nameVal -is [string]) -and $HyphaeHookNames.Contains($nameVal)) {
            return $true
        }
    }
    return $false
}

function Remove-HyphaeHooksFromDoc {
    param($Doc)
    if (-not (Test-JsonProperty $Doc "hooks")) {
        return 0
    }
    $hooks = $Doc.PSObject.Properties["hooks"].Value
    if (-not (Test-JsonObject $hooks)) {
        return 0
    }

    $totalRemoved = 0
    $eventsToDelete = New-Object System.Collections.Generic.List[string]
    $eventProps = @($hooks.PSObject.Properties | ForEach-Object { $_ })

    foreach ($evProp in $eventProps) {
        $eventName = $evProp.Name
        $eventVal = $evProp.Value
        if ($null -eq $eventVal -or (-not ($eventVal -is [System.Collections.IList]))) {
            continue
        }
        $eventRemoved = 0
        $newList = New-Object System.Collections.Generic.List[object]
        foreach ($item in $eventVal) {
            if ((Test-JsonObject $item) -and (Test-JsonProperty $item "hooks") -and ($item.PSObject.Properties["hooks"].Value -is [System.Collections.IList])) {
                $origSub = $item.PSObject.Properties["hooks"].Value
                $keptSub = New-Object System.Collections.Generic.List[object]
                foreach ($h in $origSub) {
                    if (-not (Test-HyphaeHookLeaf $h)) {
                        $keptSub.Add($h)
                    }
                }
                $diff = ([System.Collections.ICollection]$origSub).Count - $keptSub.Count
                if ($diff -gt 0) {
                    $eventRemoved += $diff
                    if ($keptSub.Count -gt 0) {
                        $item.PSObject.Properties["hooks"].Value = [object[]]$keptSub.ToArray()
                        $newList.Add($item)
                    }
                } else {
                    $newList.Add($item)
                }
            } elseif (Test-HyphaeHookLeaf $item) {
                $eventRemoved += 1
            } else {
                $newList.Add($item)
            }
        }
        if ($eventRemoved -gt 0) {
            $totalRemoved += $eventRemoved
            if ($newList.Count -gt 0) {
                $hooks.PSObject.Properties[$eventName].Value = [object[]]$newList.ToArray()
            } else {
                $eventsToDelete.Add($eventName)
            }
        }
    }

    foreach ($ev in $eventsToDelete) {
        $hooks.PSObject.Properties.Remove($ev)
    }
    if ($totalRemoved -gt 0 -and (Get-JsonPropertyCount $hooks) -eq 0) {
        $Doc.PSObject.Properties.Remove("hooks")
    }
    return $totalRemoved
}

function Remove-NestedJsonKey {
    param(
        $Doc,
        [string[]]$Parents,
        [string]$Key
    )
    $chain = New-Object System.Collections.Generic.List[object]
    $cur = $Doc
    foreach ($p in $Parents) {
        if (-not (Test-JsonProperty $cur $p)) {
            return $false
        }
        $next = $cur.PSObject.Properties[$p].Value
        if (-not (Test-JsonObject $next)) {
            return $false
        }
        $chain.Add([PSCustomObject]@{ Obj = $cur; Key = $p })
        $cur = $next
    }
    if (-not (Test-JsonProperty $cur $Key)) {
        return $false
    }
    $cur.PSObject.Properties.Remove($Key)
    for ($i = $chain.Count - 1; $i -ge 0; $i--) {
        $entry = $chain[$i]
        $child = $entry.Obj.PSObject.Properties[$entry.Key].Value
        if ((Test-JsonObject $child) -and (Get-JsonPropertyCount $child) -eq 0) {
            $entry.Obj.PSObject.Properties.Remove($entry.Key)
        } else {
            break
        }
    }
    return $true
}

function Update-StatusLineInDoc {
    param(
        $Doc,
        [string]$Harness,
        [string]$FilePath,
        [string[]]$ChainSearchDirs,
        [System.Collections.Generic.List[string]]$StatusLinePlans
    )
    if (-not (Test-JsonProperty $Doc "statusLine")) {
        return $false
    }
    $sl = $Doc.PSObject.Properties["statusLine"].Value
    if (-not (Test-JsonObject $sl)) {
        return $false
    }
    if (-not (Test-JsonProperty $sl "command")) {
        return $false
    }
    $cmd = $sl.PSObject.Properties["command"].Value
    if ((-not ($cmd -is [string])) -or (-not (Test-HyphaeStatusLineCommand $cmd))) {
        return $false
    }

    $backup = Find-StatusLineChainBackup -Harness $Harness -Cmd $cmd -SearchDirs $ChainSearchDirs
    if ($null -ne $backup) {
        $Doc.PSObject.Properties["statusLine"].Value = $backup.Value
        $StatusLinePlans.Add("${FilePath}: restore original ${Harness} statusLine from $($backup.Path)")
    } else {
        $Doc.PSObject.Properties.Remove("statusLine")
        $StatusLinePlans.Add("${FilePath}: remove Hyphae ${Harness} statusLine")
    }
    return $true
}

function Test-CodexHyphaeHeader {
    param([string]$Line)
    $trimmed = $Line.Trim()
    if ((-not $trimmed.StartsWith("[")) -or $trimmed.StartsWith("[[")) {
        return $false
    }
    $closeIdx = $trimmed.IndexOf("]")
    if ($closeIdx -lt 0) {
        return $false
    }
    $trailing = $trimmed.Substring($closeIdx + 1).Trim()
    if ((-not [string]::IsNullOrEmpty($trailing)) -and (-not $trailing.StartsWith("#"))) {
        return $false
    }
    $inner = ($trimmed.Substring(1, $closeIdx - 1) -replace '\s+', '')
    return (
        ($inner -in @("mcp_servers.hyphae", 'mcp_servers."hyphae"', "mcp_servers.'hyphae'")) -or
        $inner.StartsWith("mcp_servers.hyphae.") -or
        $inner.StartsWith('mcp_servers."hyphae".') -or
        $inner.StartsWith("mcp_servers.'hyphae'.")
    )
}

function Clean-CodexTomlText {
    param([string]$Raw)
    $newline = if ($Raw.Contains("`r`n")) { "`r`n" } else { "`n" }
    $lines = $Raw -split '\r?\n'
    $kept = New-Object System.Collections.Generic.List[string]
    $removedManaged = $false
    $removedSection = $false
    $inManaged = $false
    $inHyphaeSection = $false
    $justRemoved = $false

    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($inManaged) {
            if ($trimmed -eq "# <<< hyphae <<<") {
                $inManaged = $false
                $justRemoved = $true
            }
            continue
        }
        if ($trimmed -eq "# >>> hyphae >>>") {
            $inManaged = $true
            $removedManaged = $true
            continue
        }
        if ($inHyphaeSection) {
            if ($trimmed.StartsWith("[")) {
                $inHyphaeSection = $false
                $justRemoved = $true
            } else {
                continue
            }
        }
        if (Test-CodexHyphaeHeader $line) {
            $inHyphaeSection = $true
            $removedSection = $true
            continue
        }
        if ($justRemoved -and $trimmed -eq "") {
            if ($kept.Count -eq 0 -or $kept[$kept.Count - 1].Trim() -eq "") {
                continue
            }
        }
        $justRemoved = $false
        $kept.Add($line)
    }

    if ((-not $removedManaged) -and (-not $removedSection)) {
        return [PSCustomObject]@{
            Text    = $Raw
            Reasons = [string[]]@()
        }
    }

    while ($kept.Count -gt 0 -and $kept[$kept.Count - 1].Trim() -eq "") {
        $kept.RemoveAt($kept.Count - 1)
    }
    while ($kept.Count -gt 0 -and $kept[0].Trim() -eq "") {
        $kept.RemoveAt(0)
    }

    $nextText = if ($kept.Count -gt 0) { ($kept.ToArray() -join $newline) + $newline } else { "" }
    $reasons = New-Object System.Collections.Generic.List[string]
    if ($removedManaged) {
        $reasons.Add("# >>> hyphae >>> managed block")
    }
    if ($removedSection) {
        $reasons.Add("[mcp_servers.hyphae] section")
    }
    return [PSCustomObject]@{
        Text    = $nextText
        Reasons = [string[]]$reasons.ToArray()
    }
}

# Build chain backup search dirs (used BEFORE state wipe so statusLines restore cleanly).
$ChainSearchDirsList = New-Object System.Collections.Generic.List[string]
$ChainSearchDirsSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($candDir in @(
    $StateDir,
    $env:HYPHAE_STATE_DIR,
    $env:HYPHAE_CONFIG_DIR,
    (Join-Path $AppData "hyphae"),
    (Join-Path $ConfigHome "hyphae"),
    (Join-Path (Join-Path $UserHome ".config") "hyphae"),
    (Join-Path $LocalAppData "hyphae")
)) {
    Add-UniquePath -List $ChainSearchDirsList -Seen $ChainSearchDirsSeen -Path $candDir
}
$ChainSearchDirs = [string[]]$ChainSearchDirsList.ToArray()

function Invoke-HarnessConfigCleaner {
    param([ValidateSet("plan", "apply")][string]$Mode)

    $statusLines = New-Object System.Collections.Generic.List[string]
    $edits = New-Object System.Collections.Generic.List[string]
    $layoutNotes = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]

    # 1. Claude Code %USERPROFILE%\.claude\settings.json (+ optional CLAUDE_CONFIG_DIR\settings.json)
    $claudeSettingsFiles = New-Object System.Collections.Generic.List[string]
    $claudeSettingsSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    Add-UniquePath -List $claudeSettingsFiles -Seen $claudeSettingsSeen -Path (Join-Path (Join-Path $UserHome ".claude") "settings.json")
    if (-not [string]::IsNullOrWhiteSpace($ClaudeProfileDir)) {
        Add-UniquePath -List $claudeSettingsFiles -Seen $claudeSettingsSeen -Path (Join-Path $ClaudeProfileDir "settings.json")
    }
    foreach ($csPath in $claudeSettingsFiles) {
        if (Test-Path -LiteralPath $csPath -PathType Leaf) {
            $doc = Read-JsonObject -Path $csPath -Warnings $warnings
            if ($null -ne $doc) {
                $slChanged = Update-StatusLineInDoc -Doc $doc -Harness "claude" -FilePath $csPath -ChainSearchDirs $ChainSearchDirs -StatusLinePlans $statusLines
                $hooksRemoved = Remove-HyphaeHooksFromDoc -Doc $doc
                if ($hooksRemoved -gt 0) {
                    $edits.Add("${csPath}: remove ${hooksRemoved} Hyphae hook entry/entries")
                }
                if ($Mode -eq "apply" -and ($slChanged -or $hooksRemoved -gt 0)) {
                    Save-JsonObject -Path $csPath -Doc $doc
                }
            }
        }
    }

    # 2. Antigravity CLI %USERPROFILE%\.gemini\antigravity-cli\settings.json (statusLine FIRST)
    $agySettings = Join-Path (Join-Path (Join-Path $UserHome ".gemini") "antigravity-cli") "settings.json"
    if (Test-Path -LiteralPath $agySettings -PathType Leaf) {
        $doc = Read-JsonObject -Path $agySettings -Warnings $warnings
        if ($null -ne $doc) {
            $slChanged = Update-StatusLineInDoc -Doc $doc -Harness "antigravity" -FilePath $agySettings -ChainSearchDirs $ChainSearchDirs -StatusLinePlans $statusLines
            if ($Mode -eq "apply" -and $slChanged) {
                Save-JsonObject -Path $agySettings -Doc $doc
            }
        }
    }

    # 3. Claude Code %USERPROFILE%\.claude.json (+ CLAUDE_CONFIG_DIR\.claude.json) & Claude Desktop claude_desktop_config.json
    $claudeMcpFiles = New-Object System.Collections.Generic.List[string]
    $claudeMcpSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    Add-UniquePath -List $claudeMcpFiles -Seen $claudeMcpSeen -Path (Join-Path $UserHome ".claude.json")
    if (-not [string]::IsNullOrWhiteSpace($ClaudeProfileDir)) {
        Add-UniquePath -List $claudeMcpFiles -Seen $claudeMcpSeen -Path (Join-Path $ClaudeProfileDir ".claude.json")
    }
    Add-UniquePath -List $claudeMcpFiles -Seen $claudeMcpSeen -Path (Join-Path (Join-Path $AppData "Claude") "claude_desktop_config.json")
    Add-UniquePath -List $claudeMcpFiles -Seen $claudeMcpSeen -Path (Join-Path (Join-Path $ConfigHome "Claude") "claude_desktop_config.json")
    Add-UniquePath -List $claudeMcpFiles -Seen $claudeMcpSeen -Path (Join-Path (Join-Path (Join-Path $UserHome ".config") "Claude") "claude_desktop_config.json")
    foreach ($mcpPath in $claudeMcpFiles) {
        if (Test-Path -LiteralPath $mcpPath -PathType Leaf) {
            $doc = Read-JsonObject -Path $mcpPath -Warnings $warnings
            if ($null -ne $doc) {
                if (Remove-NestedJsonKey -Doc $doc -Parents @("mcpServers") -Key "hyphae") {
                    $edits.Add("${mcpPath}: remove mcpServers.hyphae")
                    if ($Mode -eq "apply") {
                        Save-JsonObject -Path $mcpPath -Doc $doc
                    }
                }
            }
        }
    }

    # 4. Gemini CLI %USERPROFILE%\.gemini\settings.json
    $geminiSettings = Join-Path (Join-Path $UserHome ".gemini") "settings.json"
    if (Test-Path -LiteralPath $geminiSettings -PathType Leaf) {
        $doc = Read-JsonObject -Path $geminiSettings -Warnings $warnings
        if ($null -ne $doc) {
            $reasons = New-Object System.Collections.Generic.List[string]
            if (Remove-NestedJsonKey -Doc $doc -Parents @("mcpServers") -Key "hyphae") {
                $reasons.Add("mcpServers.hyphae")
            }
            $hooksRemoved = Remove-HyphaeHooksFromDoc -Doc $doc
            if ($hooksRemoved -gt 0) {
                $reasons.Add("${hooksRemoved} Hyphae hook entry/entries")
            }
            if ($reasons.Count -gt 0) {
                $edits.Add("${geminiSettings}: remove " + ($reasons.ToArray() -join " + "))
                if ($Mode -eq "apply") {
                    Save-JsonObject -Path $geminiSettings -Doc $doc
                }
            }
        }
    }

    # 5. Cursor %USERPROFILE%\.cursor\mcp.json & hooks.json
    $cursorMcp = Join-Path (Join-Path $UserHome ".cursor") "mcp.json"
    if (Test-Path -LiteralPath $cursorMcp -PathType Leaf) {
        $doc = Read-JsonObject -Path $cursorMcp -Warnings $warnings
        if ($null -ne $doc) {
            if (Remove-NestedJsonKey -Doc $doc -Parents @("mcpServers") -Key "hyphae") {
                $edits.Add("${cursorMcp}: remove mcpServers.hyphae")
                if ($Mode -eq "apply") {
                    Save-JsonObject -Path $cursorMcp -Doc $doc
                }
            }
        }
    }

    $cursorHooks = Join-Path (Join-Path $UserHome ".cursor") "hooks.json"
    if (Test-Path -LiteralPath $cursorHooks -PathType Leaf) {
        $doc = Read-JsonObject -Path $cursorHooks -Warnings $warnings
        if ($null -ne $doc) {
            $hooksRemoved = Remove-HyphaeHooksFromDoc -Doc $doc
            if ($hooksRemoved -gt 0) {
                $edits.Add("${cursorHooks}: remove ${hooksRemoved} Hyphae hook entry/entries")
                if ($Mode -eq "apply") {
                    Save-JsonObject -Path $cursorHooks -Doc $doc
                }
            }
        }
    }

    # 6. Codex %USERPROFILE%\.codex\hooks.json & config.toml
    $codexHooks = Join-Path (Join-Path $UserHome ".codex") "hooks.json"
    if (Test-Path -LiteralPath $codexHooks -PathType Leaf) {
        $doc = Read-JsonObject -Path $codexHooks -Warnings $warnings
        if ($null -ne $doc) {
            $hooksRemoved = Remove-HyphaeHooksFromDoc -Doc $doc
            if ($hooksRemoved -gt 0) {
                $edits.Add("${codexHooks}: remove ${hooksRemoved} Hyphae hook entry/entries")
                if ($Mode -eq "apply") {
                    Save-JsonObject -Path $codexHooks -Doc $doc
                }
            }
        }
    }

    $codexToml = Join-Path (Join-Path $UserHome ".codex") "config.toml"
    if (Test-Path -LiteralPath $codexToml -PathType Leaf) {
        try {
            $rawToml = [System.IO.File]::ReadAllText($codexToml, [System.Text.Encoding]::UTF8)
            $cleaned = Clean-CodexTomlText -Raw $rawToml
            if ($cleaned.Reasons.Count -gt 0) {
                $edits.Add("${codexToml}: remove " + ($cleaned.Reasons -join " + "))
                if ($Mode -eq "apply") {
                    Write-AtomicUtf8Text -Path $codexToml -Content $cleaned.Text
                }
            }
        } catch {
            $warnings.Add("${codexToml}: skipped unreadable TOML ($($_.Exception.Message))")
        }
    }

    # 7. OpenCode opencode.json
    $opencodeFiles = New-Object System.Collections.Generic.List[string]
    $opencodeSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    Add-UniquePath -List $opencodeFiles -Seen $opencodeSeen -Path (Join-Path (Join-Path $ConfigHome "opencode") "opencode.json")
    Add-UniquePath -List $opencodeFiles -Seen $opencodeSeen -Path (Join-Path (Join-Path (Join-Path $UserHome ".config") "opencode") "opencode.json")
    Add-UniquePath -List $opencodeFiles -Seen $opencodeSeen -Path (Join-Path (Join-Path $AppData "opencode") "opencode.json")
    foreach ($ocPath in $opencodeFiles) {
        if (Test-Path -LiteralPath $ocPath -PathType Leaf) {
            $doc = Read-JsonObject -Path $ocPath -Warnings $warnings
            if ($null -ne $doc) {
                $reasons = New-Object System.Collections.Generic.List[string]
                if (Remove-NestedJsonKey -Doc $doc -Parents @("mcp") -Key "hyphae") {
                    $reasons.Add("mcp.hyphae")
                }
                if (Remove-NestedJsonKey -Doc $doc -Parents @("mcpServers") -Key "hyphae") {
                    $reasons.Add("mcpServers.hyphae")
                }
                if ($reasons.Count -gt 0) {
                    $edits.Add("${ocPath}: remove " + ($reasons.ToArray() -join " + "))
                    if ($Mode -eq "apply") {
                        Save-JsonObject -Path $ocPath -Doc $doc
                    }
                }
            }
        }
    }

    # 8. OpenClaw %USERPROFILE%\.openclaw\openclaw.json
    $openclawJson = Join-Path (Join-Path $UserHome ".openclaw") "openclaw.json"
    if (Test-Path -LiteralPath $openclawJson -PathType Leaf) {
        $doc = Read-JsonObject -Path $openclawJson -Warnings $warnings
        if ($null -ne $doc) {
            $reasons = New-Object System.Collections.Generic.List[string]
            if (Remove-NestedJsonKey -Doc $doc -Parents @("mcp", "servers") -Key "hyphae") {
                $reasons.Add("mcp.servers.hyphae")
            }
            if (Remove-NestedJsonKey -Doc $doc -Parents @("mcpServers") -Key "hyphae") {
                $reasons.Add("mcpServers.hyphae")
            }
            if (Remove-NestedJsonKey -Doc $doc -Parents @("plugins", "entries") -Key "hyphae") {
                $reasons.Add("plugins.entries.hyphae")
            }
            if ((Test-JsonProperty $doc "plugins")) {
                $pluginsObj = $doc.PSObject.Properties["plugins"].Value
                if ((Test-JsonObject $pluginsObj) -and (Test-JsonProperty $pluginsObj "allow")) {
                    $allowVal = $pluginsObj.PSObject.Properties["allow"].Value
                    if ($allowVal -is [System.Collections.IList]) {
                        $kept = @($allowVal | Where-Object { $_ -ne "hyphae" })
                        if ($kept.Count -ne $allowVal.Count) {
                            if ($kept.Count -gt 0) {
                                $pluginsObj.PSObject.Properties["allow"].Value = $kept
                            } else {
                                $pluginsObj.PSObject.Properties.Remove("allow")
                            }
                            if ((@($pluginsObj.PSObject.Properties).Count) -eq 0) {
                                $doc.PSObject.Properties.Remove("plugins")
                            }
                            $reasons.Add("plugins.allow[hyphae]")
                        }
                    }
                }
            }
            if ($reasons.Count -gt 0) {
                $edits.Add("${openclawJson}: remove " + ($reasons.ToArray() -join " + "))
                if ($Mode -eq "apply") {
                    Save-JsonObject -Path $openclawJson -Doc $doc
                }
            }
        }
    }

    # 9. Native Herdr App keys.json & read-only layout inspection
    $herdrDirs = New-Object System.Collections.Generic.List[string]
    $herdrSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    Add-UniquePath -List $herdrDirs -Seen $herdrSeen -Path $HerdrAppDir
    Add-UniquePath -List $herdrDirs -Seen $herdrSeen -Path (Join-Path (Join-Path $UserHome ".config") "herdr-app")
    foreach ($hdir in $herdrDirs) {
        $keysPath = Join-Path $hdir "keys.json"
        if (Test-Path -LiteralPath $keysPath -PathType Leaf) {
            $doc = Read-JsonObject -Path $keysPath -Warnings $warnings
            if ($null -ne $doc -and (Test-JsonProperty $doc "global")) {
                $g = $doc.PSObject.Properties["global"].Value
                if ((Test-JsonObject $g) -and (Test-JsonProperty $g "cmd-shift-h") -and ($g.PSObject.Properties["cmd-shift-h"].Value -eq "mod.open:hyphae-panel")) {
                    $g.PSObject.Properties.Remove("cmd-shift-h")
                    $edits.Add("${keysPath}: remove global.`"cmd-shift-h`" -> `"mod.open:hyphae-panel`"")
                    if ($Mode -eq "apply") {
                        Save-JsonObject -Path $keysPath -Doc $doc
                    }
                }
            }
        }

        $layoutsDir = Join-Path $hdir "layouts"
        if (Test-Path -LiteralPath $layoutsDir -PathType Container) {
            $layoutFiles = Get-ChildItem -LiteralPath $layoutsDir -File -ErrorAction SilentlyContinue | Sort-Object Name
            foreach ($lf in @($layoutFiles)) {
                if ($null -eq $lf) { continue }
                if ((-not $lf.Name.EndsWith(".json", [System.StringComparison]::OrdinalIgnoreCase)) -or ($lf.Name.IndexOf(".bak.", [System.StringComparison]::OrdinalIgnoreCase) -ge 0)) {
                    continue
                }
                try {
                    $ltext = [System.IO.File]::ReadAllText($lf.FullName, [System.Text.Encoding]::UTF8)
                } catch {
                    continue
                }
                $refs = New-Object System.Collections.Generic.List[string]
                if ($ltext.Contains('"hyphae-pane"')) { $refs.Add("hyphae-pane") }
                if ($ltext.Contains('"hyphae-panel"')) { $refs.Add("hyphae-panel") }
                if ($refs.Count -gt 0) {
                    $layoutNotes.Add("$($lf.FullName): references $($refs.ToArray() -join ', ') (left untouched)")
                }
            }
        }
    }

    return [PSCustomObject]@{
        StatusLines = $statusLines
        Edits       = $edits
        LayoutNotes = $layoutNotes
        Warnings    = $warnings
    }
}

# ---------------------------------------------------------------------------
# 1. Discover targets to clean (read-only)
# ---------------------------------------------------------------------------

$BinPath = Join-Path $InstallDir "hyp.exe"
$HasScheduledTask = $false
if ($IsRealProfile) {
    $HasScheduledTask = Test-ScheduledTaskExists -TaskName "HyphaeDaemon"
}
$DaemonProcs = Find-HyphaeDaemonProcesses

$PlanWarnings = New-Object System.Collections.Generic.List[string]
$StatusLinePlans = New-Object System.Collections.Generic.List[string]
$ConfigEditPlans = New-Object System.Collections.Generic.List[string]
$LayoutNotes = New-Object System.Collections.Generic.List[string]
$StandaloneHarnessPaths = New-Object System.Collections.Generic.List[string]
$SkillDirsToRemove = New-Object System.Collections.Generic.List[string]

if (-not $KeepHarnesses) {
    $cleanPlan = Invoke-HarnessConfigCleaner -Mode "plan"
    foreach ($item in $cleanPlan.StatusLines) { $StatusLinePlans.Add($item) }
    foreach ($item in $cleanPlan.Edits) { $ConfigEditPlans.Add($item) }
    foreach ($item in $cleanPlan.LayoutNotes) { $LayoutNotes.Add($item) }
    foreach ($item in $cleanPlan.Warnings) { $PlanWarnings.Add($item) }

    # Standalone Claude Code slash commands
    $standaloneSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $claudeCmdDirs = New-Object System.Collections.Generic.List[string]
    $claudeCmdDirSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    Add-UniquePath -List $claudeCmdDirs -Seen $claudeCmdDirSeen -Path (Join-Path (Join-Path $UserHome ".claude") "commands")
    if (-not [string]::IsNullOrWhiteSpace($ClaudeProfileDir)) {
        Add-UniquePath -List $claudeCmdDirs -Seen $claudeCmdDirSeen -Path (Join-Path $ClaudeProfileDir "commands")
    }
    foreach ($cmdDir in $claudeCmdDirs) {
        if (Test-Path -LiteralPath $cmdDir -PathType Container) {
            foreach ($cmdName in @("hyphae.md", "hyphae-subs.md", "hyphae-focus.md", "hyphae-mute.md")) {
                $p = Join-Path $cmdDir $cmdName
                if (Test-Path -LiteralPath $p) {
                    Add-UniquePath -List $StandaloneHarnessPaths -Seen $standaloneSeen -Path $p
                }
            }
        }
    }

    # Standalone harness plugins, manifests & Herdr mods
    foreach ($p in @(
        (Join-Path $UserHome ".gemini\config\plugins\hyphae"),
        (Join-Path $ConfigHome "opencode\plugins\hyphae.ts"),
        (Join-Path $UserHome ".config\opencode\plugins\hyphae.ts"),
        (Join-Path $AppData "opencode\plugins\hyphae.ts"),
        (Join-Path $UserHome ".openclaw\extensions\hyphae"),
        (Join-Path $ConfigHome "herdr\hyphae.json"),
        (Join-Path $UserHome ".config\herdr\hyphae.json"),
        (Join-Path $UserHome ".t3\hyphae.json"),
        (Join-Path $HerdrAppDir "mods\hyphae-pane"),
        (Join-Path $HerdrAppDir "mods\hyphae-panel"),
        (Join-Path $UserHome ".config\herdr-app\mods\hyphae-pane"),
        (Join-Path $UserHome ".config\herdr-app\mods\hyphae-panel")
    )) {
        if ((Test-Path -LiteralPath $p) -and (Test-SafeRemovalPath $p)) {
            Add-UniquePath -List $StandaloneHarnessPaths -Seen $standaloneSeen -Path $p
        }
    }

    # Installed Hyphae skill subdirectories across harness roots
    $skillRoots = New-Object System.Collections.Generic.List[string]
    $skillRootSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    Add-UniquePath -List $skillRoots -Seen $skillRootSeen -Path (Join-Path $UserHome ".claude\skills")
    if (-not [string]::IsNullOrWhiteSpace($ClaudeProfileDir)) {
        Add-UniquePath -List $skillRoots -Seen $skillRootSeen -Path (Join-Path $ClaudeProfileDir "skills")
    }
    foreach ($sr in @(
        (Join-Path $UserHome ".codex\skills"),
        (Join-Path $UserHome ".agents\skills"),
        (Join-Path $UserHome ".gemini\config\skills"),
        (Join-Path $UserHome ".gemini\skills"),
        (Join-Path $ConfigHome "opencode\skills"),
        (Join-Path $UserHome ".config\opencode\skills"),
        (Join-Path $AppData "opencode\skills"),
        (Join-Path $UserHome ".cursor\skills"),
        (Join-Path $UserHome ".openclaw\skills"),
        (Join-Path $ConfigHome "herdr\skills"),
        (Join-Path $UserHome ".config\herdr\skills"),
        (Join-Path $UserHome ".t3\skills")
    )) {
        Add-UniquePath -List $skillRoots -Seen $skillRootSeen -Path $sr
    }

    $skillSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rootDir in $skillRoots) {
        if (Test-Path -LiteralPath $rootDir -PathType Container) {
            foreach ($skillName in @("hyphae", "hyphae-setup", "hyphae-schedule", "hyphae-panel")) {
                $s = Join-Path $rootDir $skillName
                if ((Test-Path -LiteralPath $s) -and (Test-SafeRemovalPath $s)) {
                    Add-UniquePath -List $SkillDirsToRemove -Seen $skillSeen -Path $s
                }
            }
        }
    }
}

# State & config directories to remove (unless -KeepState)
$StateDirsToRemove = New-Object System.Collections.Generic.List[string]
$StateDirsSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
if (-not $KeepState) {
    $candidateStateDirs = New-Object System.Collections.Generic.List[string]
    if ($ExplicitStateDir) {
        $candidateStateDirs.Add($StateDir)
    } else {
        if (-not [string]::IsNullOrWhiteSpace($env:HYPHAE_STATE_DIR)) {
            $candidateStateDirs.Add($env:HYPHAE_STATE_DIR)
        }
        if (-not [string]::IsNullOrWhiteSpace($env:HYPHAE_CONFIG_DIR)) {
            $candidateStateDirs.Add($env:HYPHAE_CONFIG_DIR)
        }
        $candidateStateDirs.Add((Join-Path $AppData "hyphae"))
        $candidateStateDirs.Add((Join-Path $ConfigHome "hyphae"))
        $candidateStateDirs.Add((Join-Path (Join-Path $UserHome ".config") "hyphae"))
        $candidateStateDirs.Add((Join-Path (Join-Path $UserHome ".config") "agents-mesh"))
    }

    foreach ($candDir in $candidateStateDirs) {
        if ([string]::IsNullOrWhiteSpace($candDir)) {
            continue
        }
        if (-not (Test-SafeRemovalPath $candDir)) {
            $PlanWarnings.Add("Skipped unsafe state directory path: ${candDir}")
            continue
        }
        if (Test-Path -LiteralPath $candDir) {
            Add-UniquePath -List $StateDirsToRemove -Seen $StateDirsSeen -Path $candDir
        }
    }
}

# Binaries, InstallDir & User PATH discovery (unless -KeepBinary)
$BinsToRemove = New-Object System.Collections.Generic.List[string]
$BinsSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$InstallDirWillBeRemoved = $false
$StripInstallDirFromPath = $false

if (-not $KeepBinary) {
    if (Test-Path -LiteralPath $InstallDir -PathType Container) {
        foreach ($binName in @("hyp.exe", "hyp.exe.old", "hyp.old.exe", "hyp.prev.exe", "hyp-rs.exe")) {
            $b = Join-Path $InstallDir $binName
            if ((Test-Path -LiteralPath $b) -and (Test-SafeRemovalPath $b)) {
                Add-UniquePath -List $BinsToRemove -Seen $BinsSeen -Path $b
            }
        }
        # Match unique rename-aside backups (hyp.exe.old.<hex>) and interrupted staging files (.hyp.tmp.*.exe).
        $extraMatches = Get-ChildItem -LiteralPath $InstallDir -File -Force -ErrorAction SilentlyContinue | Where-Object {
            ($_.Name -like "hyp.exe.old.*") -or ($_.Name -like ".hyp.tmp.*.exe")
        }
        foreach ($extra in @($extraMatches)) {
            if ($null -ne $extra -and (Test-SafeRemovalPath $extra.FullName)) {
                Add-UniquePath -List $BinsToRemove -Seen $BinsSeen -Path $extra.FullName
            }
        }

        # Check whether $InstallDir will be empty after removing Hyphae binaries.
        $allEntries = @(Get-ChildItem -LiteralPath $InstallDir -Force -ErrorAction SilentlyContinue)
        $remainingCount = 0
        foreach ($ent in $allEntries) {
            if ($null -eq $ent) { continue }
            $normEnt = Get-NormalizedPath $ent.FullName
            if (-not $BinsSeen.Contains($normEnt)) {
                $remainingCount++
            }
        }
        if ($remainingCount -eq 0 -and (Test-SafeRemovalPath $InstallDir)) {
            $InstallDirWillBeRemoved = $true
        }
    }

    if ($IsRealProfile -and (Test-UserPathContains -Dir $InstallDir)) {
        $isDedicatedHyphaeDir = (Test-PathEquals $InstallDir $DefaultInstallDir) -or ($InstallDir.TrimEnd('\', '/') -match '(?i)[\\/]hyphae[\\/]bin$')
        if ($isDedicatedHyphaeDir -or $InstallDirWillBeRemoved -or (-not (Test-Path -LiteralPath $InstallDir))) {
            $StripInstallDirFromPath = $true
        } else {
            $PlanWarnings.Add("Preserving User PATH entry '${InstallDir}' because directory contains non-Hyphae files.")
        }
    }
}

# ---------------------------------------------------------------------------
# 2. Print scannable preview plan
# ---------------------------------------------------------------------------

$TotalActions = 0
if ($HasScheduledTask) { $TotalActions += 1 }
$TotalActions += $DaemonProcs.Count
$TotalActions += $StatusLinePlans.Count
$TotalActions += $ConfigEditPlans.Count
$TotalActions += $StandaloneHarnessPaths.Count
$TotalActions += $SkillDirsToRemove.Count
$TotalActions += $StateDirsToRemove.Count
$TotalActions += $BinsToRemove.Count
if ($InstallDirWillBeRemoved) { $TotalActions += 1 }
if ($StripInstallDirFromPath) { $TotalActions += 1 }

if (-not [string]::IsNullOrWhiteSpace($ClaudeProfileDir)) {
    Write-Output "Hyphae Windows uninstall plan (USERPROFILE=${UserHome}, CLAUDE_CONFIG_DIR=${ClaudeProfileDir})"
} else {
    Write-Output "Hyphae Windows uninstall plan (USERPROFILE=${UserHome})"
}
Write-Output "=================================================="

if ($TotalActions -eq 0) {
    Write-Output "Already clean - nothing to remove."
    if ($KeepBinary -and (Test-Path -LiteralPath $BinPath)) {
        Write-Output "Note: kept binary at ${BinPath} (omit -KeepBinary to remove it too)."
    }
    if ($KeepState) {
        Write-Output "Note: kept state directories (-KeepState)."
    }
    if ($KeepHarnesses) {
        Write-Output "Note: kept harness configs (-KeepHarnesses)."
    }
    if ($LayoutNotes.Count -gt 0) {
        Write-Output ""
        Write-Output "Herdr layout notes (not modified):"
        foreach ($note in $LayoutNotes) {
            Write-Output "  - ${note}"
        }
    }
    return
}

if ($HasScheduledTask -or $DaemonProcs.Count -gt 0) {
    Write-Output ""
    Write-Output "1. Scheduled task & running daemons to stop/remove:"
    if ($HasScheduledTask) {
        Write-Output "  - Windows Task Scheduler task: HyphaeDaemon"
    }
    foreach ($proc in $DaemonProcs) {
        Write-Output "  - Process PID $($proc.Pid): $($proc.CommandLine)"
    }
}

if ($StatusLinePlans.Count -gt 0) {
    Write-Output ""
    Write-Output "2. StatusLines to restore/remove ($($StatusLinePlans.Count)):"
    foreach ($sl in $StatusLinePlans) {
        Write-Output "  - ${sl}"
    }
}

if ($ConfigEditPlans.Count -gt 0) {
    Write-Output ""
    Write-Output "3. Shared harness configs to edit surgically ($($ConfigEditPlans.Count)):"
    foreach ($ed in $ConfigEditPlans) {
        Write-Output "  - ${ed}"
    }
}

if ($StandaloneHarnessPaths.Count -gt 0) {
    Write-Output ""
    Write-Output "4. Standalone Hyphae plugins, commands & Herdr mods to remove ($($StandaloneHarnessPaths.Count)):"
    foreach ($sp in $StandaloneHarnessPaths) {
        Write-Output "  - ${sp}"
    }
}

if ($SkillDirsToRemove.Count -gt 0) {
    Write-Output ""
    Write-Output "4. Installed Hyphae skill folders to remove ($($SkillDirsToRemove.Count)):"
    foreach ($sk in $SkillDirsToRemove) {
        Write-Output "  - ${sk}"
    }
}

if ($StateDirsToRemove.Count -gt 0) {
    Write-Output ""
    Write-Output "5. Config / state directories to remove ($($StateDirsToRemove.Count)):"
    foreach ($sd in $StateDirsToRemove) {
        Write-Output "  - ${sd}"
    }
} elseif ($KeepState) {
    Write-Output ""
    Write-Output "5. Keeping state directories (-KeepState)"
}

if ($BinsToRemove.Count -gt 0 -or $InstallDirWillBeRemoved -or $StripInstallDirFromPath) {
    Write-Output ""
    Write-Output "6. Binaries, install directory & User PATH cleanup:"
    foreach ($b in $BinsToRemove) {
        Write-Output "  - Binary: ${b}"
    }
    if ($InstallDirWillBeRemoved) {
        Write-Output "  - Empty install directory: ${InstallDir}"
    }
    if ($StripInstallDirFromPath) {
        Write-Output "  - Strip from User PATH: ${InstallDir}"
    }
} elseif ($KeepBinary -and (Test-Path -LiteralPath $BinPath)) {
    Write-Output ""
    Write-Output "6. Keeping binary: ${BinPath} (-KeepBinary)"
}

if ($LayoutNotes.Count -gt 0) {
    Write-Output ""
    Write-Output "Herdr layout notes (will NOT be modified):"
    foreach ($note in $LayoutNotes) {
        Write-Output "  - ${note}"
    }
}

if ($PlanWarnings.Count -gt 0) {
    Write-Output ""
    Write-Output "Warnings:"
    foreach ($w in $PlanWarnings) {
        Write-Output "  - ${w}"
    }
}

if ($DryRun) {
    Write-Output ""
    Write-Output "[dry-run] No files, processes, scheduled tasks, configs, or PATH entries were modified."
    return
}

if (-not $Yes) {
    if (-not (Test-InteractiveTty)) {
        [Console]::Error.WriteLine("")
        [Console]::Error.WriteLine("error: non-interactive stdin; pass -Yes to confirm or -DryRun to preview")
        exit 2
    }
    Write-Host ""
    $reply = Read-Host "Proceed with uninstall? [y/N]"
    if ([string]::IsNullOrWhiteSpace($reply) -or ($reply.Trim() -notmatch '^(y|yes)$')) {
        Write-Output "Aborted."
        return
    }
}

# ---------------------------------------------------------------------------
# 3. Execute cleanup in exact safe order (statusLine restore BEFORE state wipe)
# ---------------------------------------------------------------------------

$RemovedItems = New-Object System.Collections.Generic.List[string]
$PreservedItems = New-Object System.Collections.Generic.List[string]
$ExecWarnings = New-Object System.Collections.Generic.List[string]
foreach ($w in $PlanWarnings) {
    $ExecWarnings.Add($w)
}

# Step 1: Stop & remove HyphaeDaemon Task Scheduler service + running user-owned hyp.exe daemons
$StoppedSomething = $false
if ($HasScheduledTask) {
    $uninstalledViaCli = $false
    if (Test-Path -LiteralPath $BinPath -PathType Leaf) {
        $prevEap = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            $global:LASTEXITCODE = 0
            $null = & $BinPath service uninstall 2>$null
            if ($LASTEXITCODE -eq 0 -and (-not (Test-ScheduledTaskExists -TaskName "HyphaeDaemon"))) {
                $uninstalledViaCli = $true
            }
        } catch {
            $uninstalledViaCli = $false
        } finally {
            $ErrorActionPreference = $prevEap
        }
    }

    if (-not $uninstalledViaCli) {
        [void](Invoke-ExternalQuiet -Executable "schtasks.exe" -Arguments @("/End", "/TN", "HyphaeDaemon"))
        [void](Invoke-ExternalQuiet -Executable "schtasks.exe" -Arguments @("/Delete", "/TN", "HyphaeDaemon", "/F"))
    }

    if (-not (Test-ScheduledTaskExists -TaskName "HyphaeDaemon")) {
        $RemovedItems.Add("Scheduled task: HyphaeDaemon")
    } else {
        $ExecWarnings.Add("Could not remove Windows Task Scheduler task 'HyphaeDaemon' (try running in an elevated terminal or 'schtasks /Delete /TN HyphaeDaemon /F').")
    }
    $StoppedSomething = $true
}

if ($DaemonProcs.Count -gt 0) {
    $stoppedCount = 0
    foreach ($proc in $DaemonProcs) {
        try {
            Stop-Process -Id $proc.Pid -Force -ErrorAction Stop
            $stoppedCount++
            $StoppedSomething = $true
        } catch {
            # Process may have already exited when HyphaeDaemon stopped.
            if (-not (Get-Process -Id $proc.Pid -ErrorAction SilentlyContinue)) {
                $stoppedCount++
            } else {
                $ExecWarnings.Add("Could not stop process PID $($proc.Pid): $($_.Exception.Message)")
            }
        }
    }
    if ($stoppedCount -gt 0) {
        $RemovedItems.Add("Stopped user-owned hyp daemon process(es): ${stoppedCount}")
    }
}

if ($StoppedSomething) {
    # Give Windows a brief moment to release executable/database handles before file cleanup.
    Start-Sleep -Milliseconds 400
}

# Step 2 & 3: Restore chained statusLines FIRST & surgically clean shared harness configs
if (-not $KeepHarnesses) {
    $applied = Invoke-HarnessConfigCleaner -Mode "apply"
    if ($applied.StatusLines.Count -gt 0) {
        $RemovedItems.Add("StatusLines restored/removed: $($applied.StatusLines.Count)")
    }
    if ($applied.Edits.Count -gt 0) {
        $RemovedItems.Add("Shared harness configs surgically edited: $($applied.Edits.Count)")
        $PreservedItems.Add("All non-Hyphae MCP servers, hooks, and settings in edited harness configs")
    }
} else {
    $PreservedItems.Add("Harness configs, skills, slash commands, and statusLines (-KeepHarnesses)")
}

# Step 4: Remove standalone Hyphae harness plugins, commands, Herdr mods & skill directories
$removedStandalone = 0
foreach ($sp in $StandaloneHarnessPaths) {
    try {
        if (Remove-PathSafely -Path $sp -Recurse) {
            $removedStandalone++
        }
    } catch {
        $ExecWarnings.Add("Failed to remove '${sp}': $($_.Exception.Message)")
    }
}
if ($removedStandalone -gt 0) {
    $RemovedItems.Add("Standalone Hyphae harness artifacts removed: ${removedStandalone}")
}

$removedSkills = 0
foreach ($sk in $SkillDirsToRemove) {
    try {
        if (Remove-PathSafely -Path $sk -Recurse) {
            $removedSkills++
        }
    } catch {
        $ExecWarnings.Add("Failed to remove skill folder '${sk}': $($_.Exception.Message)")
    }
}
if ($removedSkills -gt 0) {
    $RemovedItems.Add("Installed Hyphae skill folders removed: ${removedSkills}")
}

# Step 5: Remove Hyphae state & config directories (AFTER statusLine restoration)
if (-not $KeepState) {
    foreach ($sd in $StateDirsToRemove) {
        try {
            if (Remove-PathSafely -Path $sd -Recurse) {
                $RemovedItems.Add("State directory: ${sd}")
            }
        } catch {
            $ExecWarnings.Add("Failed to remove state directory '${sd}': $($_.Exception.Message)")
        }
    }
} else {
    $PreservedItems.Add("Hyphae state directories, keys, and database (-KeepState)")
}

# Step 6: Remove binaries, empty install directory & strip User PATH entry
if (-not $KeepBinary) {
    foreach ($b in $BinsToRemove) {
        try {
            if (Remove-PathSafely -Path $b) {
                $RemovedItems.Add("Binary: ${b}")
            }
        } catch {
            $ExecWarnings.Add("Could not remove binary '${b}' (may still be in use by an open IDE/terminal): $($_.Exception.Message)")
        }
    }

    if (Test-Path -LiteralPath $InstallDir -PathType Container) {
        $remaining = @(Get-ChildItem -LiteralPath $InstallDir -Force -ErrorAction SilentlyContinue)
        if ($remaining.Count -eq 0 -and (Test-SafeRemovalPath $InstallDir)) {
            try {
                if (Remove-PathSafely -Path $InstallDir) {
                    $RemovedItems.Add("Install directory: ${InstallDir}")
                }
                # Clean empty parent ...\Programs\hyphae directory when using default layout.
                if (Test-PathEquals $InstallDir $DefaultInstallDir) {
                    $hyphaeRoot = [System.IO.Path]::GetDirectoryName((Get-NormalizedPath $InstallDir))
                    if ((-not [string]::IsNullOrWhiteSpace($hyphaeRoot)) -and (Test-Path -LiteralPath $hyphaeRoot -PathType Container)) {
                        $parentRemaining = @(Get-ChildItem -LiteralPath $hyphaeRoot -Force -ErrorAction SilentlyContinue)
                        if ($parentRemaining.Count -eq 0 -and (Test-SafeRemovalPath $hyphaeRoot)) {
                            [void](Remove-PathSafely -Path $hyphaeRoot)
                        }
                    }
                }
            } catch {
                $ExecWarnings.Add("Could not remove empty install directory '${InstallDir}': $($_.Exception.Message)")
            }
        }
    }

    if ($StripInstallDirFromPath) {
        try {
            if (Remove-FromUserPath -Dir $InstallDir) {
                $RemovedItems.Add("User PATH entry stripped: ${InstallDir}")
            }
        } catch {
            $ExecWarnings.Add("Could not update User PATH environment variable: $($_.Exception.Message)")
        }
    }
} else {
    if (Test-Path -LiteralPath $BinPath) {
        $PreservedItems.Add("Binary: ${BinPath} (-KeepBinary)")
    } else {
        $PreservedItems.Add("Binary and User PATH (-KeepBinary)")
    }
}

# ---------------------------------------------------------------------------
# 4. Structured summary of removed vs preserved
# ---------------------------------------------------------------------------

Write-Output ""
Write-Output "Hyphae uninstall complete!"
Write-Output "=================================================="

Write-Output "Removed / cleaned:"
if ($RemovedItems.Count -gt 0) {
    foreach ($item in $RemovedItems) {
        Write-Output "  - ${item}"
    }
} else {
    Write-Output "  - (none)"
}

Write-Output ""
Write-Output "Preserved:"
if ($PreservedItems.Count -gt 0) {
    foreach ($item in $PreservedItems) {
        Write-Output "  - ${item}"
    }
} else {
    Write-Output "  - Non-Hyphae user files, configs, and User PATH entries"
}

if ($LayoutNotes.Count -gt 0) {
    Write-Output ""
    Write-Output "Reminder - custom Herdr layout(s) still reference Hyphae mods (left untouched):"
    foreach ($note in $LayoutNotes) {
        Write-Output "  - ${note}"
    }
}

if ($ExecWarnings.Count -gt 0) {
    Write-Output ""
    Write-Output "Warnings:"
    foreach ($w in $ExecWarnings) {
        Write-Output "  - ${w}"
    }
}

Write-Output ""
if (-not $KeepBinary) {
    Write-Output "Reinstall anytime with:"
    Write-Output "  irm https://hyphae.to/install.ps1 | iex"
} else {
    Write-Output "Kept hyp.exe binary. Re-onboard anytime with:"
    Write-Output "  hyp onboard"
}
