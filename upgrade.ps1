param(
    [ValidateSet("User", "IDA", "Both")]
    [string]$InstallScope = "User",

    [string]$IdaPath = "",
    [string]$IdaPluginsDir = "",

    [switch]$ConfigureLLM,
    [ValidateSet("local", "gemini", "keep")]
    [string]$Provider = "keep",
    [string]$BaseUrl = "http://127.0.0.1:11434/v1",
    [string]$Model = "qwen2.5-coder:14b",
    [string]$ApiKey = "ollama",

    [switch]$InstallToolchain,
    [ValidateSet("Core", "Advanced", "Full")]
    [string]$ToolchainTier = "Core",
    [switch]$CreateLauncher,
    [switch]$CreateDesktopShortcut,

    [switch]$SkipBackup,
    [switch]$ResetConfig,
    [switch]$NonInteractive,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"

function Write-Step([string]$Message) {
    Write-Host "[Monstey upgrade] $Message" -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warn([string]$Message) {
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Get-ConfigDir {
    $Path = Join-Path $env:USERPROFILE ".monstey-ai-plugin"
    if (!$DryRun) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
    return $Path
}

function Test-File([string]$Path) {
    return [bool]($Path -and (Test-Path -LiteralPath $Path -PathType Leaf))
}

function Resolve-IdaExe([string]$Hint) {
    if (Test-File $Hint) {
        return (Resolve-Path -LiteralPath $Hint).Path
    }

    foreach ($Command in @("ida.exe", "ida64.exe")) {
        $Found = Get-Command $Command -ErrorAction SilentlyContinue
        if ($Found -and (Test-File $Found.Source)) {
            return $Found.Source
        }
    }

    $Patterns = @(
        (Join-Path $env:USERPROFILE "Desktop\IDA Professional*\ida.exe"),
        (Join-Path $env:USERPROFILE "Desktop\IDA*\ida.exe")
    )
    foreach ($Base in @(${env:ProgramFiles}, ${env:ProgramFiles(x86)})) {
        if ($Base) {
            $Patterns += (Join-Path $Base "IDA Professional*\ida.exe")
            $Patterns += (Join-Path $Base "IDA*\ida.exe")
        }
    }
    foreach ($Pattern in $Patterns) {
        try {
            $Match = Get-ChildItem -Path $Pattern -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($Match -and (Test-File $Match.FullName)) {
                return $Match.FullName
            }
        } catch {
        }
    }
    return ""
}

function Get-UserPluginsDir {
    return Join-Path $env:APPDATA "Hex-Rays\IDA Pro\plugins"
}

function Get-IdaPluginsDir([string]$ExePath) {
    if ($IdaPluginsDir) {
        return $IdaPluginsDir
    }
    if ($ExePath) {
        return Join-Path (Split-Path -Parent $ExePath) "plugins"
    }
    return ""
}

function Test-IsChildPath([string]$Parent, [string]$Child) {
    $ParentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd("\")
    $ChildFull = [System.IO.Path]::GetFullPath($Child)
    return $ChildFull.StartsWith($ParentFull + "\", [System.StringComparison]::OrdinalIgnoreCase)
}

function Backup-ConfigIfNeeded {
    $ConfigDir = Get-ConfigDir
    $ConfigPath = Join-Path $ConfigDir "config.json"
    if (!(Test-Path -LiteralPath $ConfigPath)) {
        return
    }
    if ($SkipBackup) {
        if ($ResetConfig) {
            if ($DryRun) {
                Write-Step "DryRun: would remove config $ConfigPath"
            } else {
                Remove-Item -LiteralPath $ConfigPath -Force
                Write-Ok "Removed old config: $ConfigPath"
            }
        }
        return
    }
    $BackupDir = Join-Path $ConfigDir "upgrade-backups\$Stamp\config"
    if ($DryRun) {
        Write-Step "DryRun: would backup config $ConfigPath to $BackupDir"
    } else {
        New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
        Copy-Item -LiteralPath $ConfigPath -Destination (Join-Path $BackupDir "config.json") -Force
        Write-Ok "Backed up config to $BackupDir"
        if ($ResetConfig) {
            Remove-Item -LiteralPath $ConfigPath -Force
            Write-Ok "Removed old config: $ConfigPath"
        }
    }
}

function Move-Or-RemoveOldPlugin([string]$PluginsDir, [string]$Label) {
    if (!$PluginsDir) {
        return
    }
    if (!(Test-Path -LiteralPath $PluginsDir -PathType Container)) {
        Write-Warn "Plugins directory not found yet: $PluginsDir"
        return
    }
    $ResolvedPluginsDir = (Resolve-Path -LiteralPath $PluginsDir).Path
    $OldNames = @(
        "Monstey-AI-plugin",
        "ida-local-game-ai",
        "idalocalgameai",
        "idalocalgameai_plugin.py",
        "idalocalgameai_diag.py",
        "ida-local-game-ai.ida-plugin.json"
    )
    $FoundAny = $false
    $BackupDir = Join-Path (Get-ConfigDir) "upgrade-backups\$Stamp\$Label"
    foreach ($Name in $OldNames) {
        $Candidate = Join-Path $ResolvedPluginsDir $Name
        if (!(Test-Path -LiteralPath $Candidate)) {
            continue
        }
        $ResolvedCandidate = (Resolve-Path -LiteralPath $Candidate).Path
        if (!(Test-IsChildPath $ResolvedPluginsDir $ResolvedCandidate)) {
            throw "Refusing to touch path outside plugins directory: $ResolvedCandidate"
        }
        $FoundAny = $true
        if ($DryRun) {
            $Action = if ($SkipBackup) { "remove" } else { "move to backup $BackupDir" }
            Write-Step "DryRun: would $Action`: $ResolvedCandidate"
            continue
        }
        if ($SkipBackup) {
            Remove-Item -LiteralPath $ResolvedCandidate -Recurse -Force
            Write-Ok "Removed old plugin path: $ResolvedCandidate"
        } else {
            New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
            Move-Item -LiteralPath $ResolvedCandidate -Destination (Join-Path $BackupDir $Name) -Force
            Write-Ok "Moved old plugin path to backup: $ResolvedCandidate"
        }
    }
    if (!$FoundAny) {
        Write-Step "No old Monstey plugin paths found in $ResolvedPluginsDir"
    }
}

function Warn-IfIdaRunning {
    $Running = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessName -in @("ida", "ida64")
    }
    if ($Running) {
        Write-Warn "IDA appears to be running. Close/restart IDA after the upgrade so Python modules reload cleanly."
    }
}

function Invoke-NewSetup([string]$ResolvedIdaPath) {
    $SetupScript = Join-Path $Root "setup.ps1"
    if (!(Test-Path -LiteralPath $SetupScript)) {
        throw "Cannot find setup.ps1 next to upgrade.ps1. Run this script from the extracted/cloned MonsteyAI-IDA-plugin folder."
    }
    $Args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $SetupScript,
        "-InstallScope", $InstallScope,
        "-Provider", $Provider
    )
    if ($ResolvedIdaPath) {
        $Args += @("-IdaPath", $ResolvedIdaPath)
    }
    if ($IdaPluginsDir) {
        $Args += @("-IdaPluginsDir", $IdaPluginsDir)
    }
    if ($ConfigureLLM) {
        $Args += @("-ConfigureLLM", "-BaseUrl", $BaseUrl, "-Model", $Model, "-ApiKey", $ApiKey)
    }
    if ($InstallToolchain) {
        $Args += @("-InstallToolchain", "-ToolchainTier", $ToolchainTier)
    }
    if ($CreateLauncher) {
        $Args += "-CreateLauncher"
    }
    if ($CreateDesktopShortcut) {
        $Args += "-CreateDesktopShortcut"
    }
    if ($NonInteractive) {
        $Args += "-NonInteractive"
    }
    if ($DryRun) {
        $Args += "-DryRun"
    }
    Write-Step "Installing the new version with setup.ps1..."
    & powershell @Args
}

Write-Step "Preparing MonsteyAI-IDA-plugin upgrade from this folder:"
Write-Host "  $Root"

Warn-IfIdaRunning
Backup-ConfigIfNeeded

$ResolvedIdaPath = Resolve-IdaExe $IdaPath
if (!$ResolvedIdaPath -and $InstallScope -in @("IDA", "Both") -and !$IdaPluginsDir) {
    throw "IDA install scope needs -IdaPath or -IdaPluginsDir."
}

$Targets = @()
if ($InstallScope -in @("User", "Both")) {
    $Targets += @{ Label = "user"; Path = Get-UserPluginsDir }
}
if ($InstallScope -in @("IDA", "Both")) {
    $Targets += @{ Label = "ida"; Path = Get-IdaPluginsDir $ResolvedIdaPath }
}

foreach ($Target in $Targets) {
    Move-Or-RemoveOldPlugin -PluginsDir $Target.Path -Label $Target.Label
}

Invoke-NewSetup -ResolvedIdaPath $ResolvedIdaPath

Write-Ok "Upgrade complete."
if (!$SkipBackup) {
    Write-Host "Backups, if any, are under:"
    Write-Host "  $(Join-Path (Get-ConfigDir) "upgrade-backups\$Stamp")"
}
Write-Host ""
Write-Host "Restart IDA, then open MonsteyAI-IDA-plugin with Ctrl+Alt+G."
