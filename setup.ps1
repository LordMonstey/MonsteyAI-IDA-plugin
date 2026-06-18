param(
    [ValidateSet("User", "IDA", "Both")]
    [string]$InstallScope = "User",

    [string]$IdaPath = "",
    [string]$IdaPluginsDir = "",

    [ValidateSet("local", "gemini", "keep")]
    [string]$Provider = "local",

    [string]$BaseUrl = "http://127.0.0.1:11434/v1",
    [string]$Model = "qwen2.5-coder:14b",
    [string]$ApiKey = "ollama",

    [switch]$ConfigureLLM,
    [switch]$InstallOllama,
    [switch]$StartOllama,
    [switch]$PullModel,
    [switch]$CreateLauncher,
    [switch]$CreateDesktopShortcut,
    [switch]$NonInteractive,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Step([string]$Message) {
    Write-Host "[Monstey setup] $Message" -ForegroundColor Cyan
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

function Invoke-PluginInstall([string]$TargetDir) {
    if (!$TargetDir) {
        throw "Missing IDA plugins directory."
    }
    $InstallScript = Join-Path $Root "install.ps1"
    if (!(Test-Path -LiteralPath $InstallScript)) {
        if (Test-Path -LiteralPath (Join-Path $Root "idalocalgameai_plugin.py")) {
            Write-Warn "install.ps1 is not next to setup.ps1; this already looks like an installed plugin folder, so file install is skipped."
            return
        }
        throw "Cannot find install.ps1 next to setup.ps1."
    }
    if ($DryRun) {
        Write-Step "DryRun: would install plugin to $TargetDir"
        return
    }
    & powershell -NoProfile -ExecutionPolicy Bypass -File $InstallScript -IdaPluginsDir $TargetDir
}

function Write-PluginConfig {
    if ($Provider -eq "keep" -and !$ConfigureLLM) {
        return
    }
    $ConfigDir = Get-ConfigDir
    $Path = Join-Path $ConfigDir "config.json"
    $Data = @{}
    if ((Test-Path -LiteralPath $Path) -and !$DryRun) {
        try {
            $Existing = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
            $Data = @{}
            if ($Existing) {
                foreach ($Property in $Existing.PSObject.Properties) {
                    $Data[$Property.Name] = $Property.Value
                }
            }
        } catch {
            $Data = @{}
        }
    }
    if ($Provider -ne "keep") {
        $Data["provider"] = $Provider
    }
    if ($ConfigureLLM) {
        $EffectiveProvider = $Provider
        if ($EffectiveProvider -eq "keep") {
            if ($Data.ContainsKey("provider") -and $Data["provider"]) {
                $EffectiveProvider = [string]$Data["provider"]
            } else {
                $EffectiveProvider = "local"
            }
        }
        $EffectiveProvider = $EffectiveProvider.ToLowerInvariant()
        $EffectiveBaseUrl = $BaseUrl
        $EffectiveModel = $Model
        $EffectiveApiKey = $ApiKey
        if ($EffectiveProvider -eq "gemini") {
            if ($EffectiveBaseUrl -eq "http://127.0.0.1:11434/v1") {
                $EffectiveBaseUrl = "https://generativelanguage.googleapis.com/v1beta/openai"
            }
            if ($EffectiveModel -eq "qwen2.5-coder:14b") {
                $EffectiveModel = "gemini-2.5-flash"
            }
            if ($EffectiveApiKey -eq "ollama") {
                $EffectiveApiKey = ""
            }
            $Data["gemini_base_url"] = $EffectiveBaseUrl
            $Data["gemini_model"] = $EffectiveModel
            $Data["gemini_api_key"] = $EffectiveApiKey
        } else {
            $Data["base_url"] = $EffectiveBaseUrl
            $Data["model"] = $EffectiveModel
            $Data["api_key"] = $EffectiveApiKey
        }
        $Data["analysis_depth"] = "Fast"
        $Data["agent_mode"] = "Single"
        $Data["timeout_seconds"] = 300
        $Data["analysis_timeout_seconds"] = 45
        $Data["max_analysis_tokens"] = 1300
        $Data["enable_global_string_scan"] = $false
    }
    if ($DryRun) {
        Write-Step "DryRun: would write config to $Path"
        return
    }
    $Data | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
    Write-Ok "Config written: $Path"
}

function Write-SetupState([string]$ResolvedIdaPath, [string[]]$InstalledDirs) {
    $ConfigDir = Get-ConfigDir
    $Path = Join-Path $ConfigDir "setup_state.json"
    $State = [ordered]@{
        version = 1
        ida_path = $ResolvedIdaPath
        installed_plugin_dirs = $InstalledDirs
        launcher = Join-Path $Root "MonsteyAI-Launcher.ps1"
        updated_at = (Get-Date).ToString("s")
    }
    if ($DryRun) {
        Write-Step "DryRun: would write setup state to $Path"
        return
    }
    $State | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Path -Encoding UTF8
    Write-Ok "Setup state written: $Path"
}

function Get-OllamaCommand {
    $Ollama = Get-Command ollama -ErrorAction SilentlyContinue
    if ($Ollama -and $Ollama.Source) {
        return $Ollama.Source
    }
    $Local = Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama.exe"
    if (Test-Path -LiteralPath $Local) {
        return $Local
    }
    return ""
}

function Install-OllamaIfRequested {
    if (!$InstallOllama) {
        return
    }
    $Existing = Get-OllamaCommand
    if ($Existing) {
        Write-Ok "Ollama already installed: $Existing"
        return
    }
    $Winget = Get-Command winget -ErrorAction SilentlyContinue
    if (!$Winget) {
        Write-Warn "winget was not found. Install Ollama from https://ollama.com/download/windows, then rerun setup with -StartOllama -PullModel."
        return
    }
    if ($DryRun) {
        Write-Step "DryRun: would install Ollama with winget"
        return
    }
    Write-Step "Installing Ollama with winget..."
    & $Winget.Source install --id Ollama.Ollama -e --accept-package-agreements --accept-source-agreements
    Start-Sleep -Seconds 2
}

function Test-Ollama {
    try {
        Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/version" -TimeoutSec 2 | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Invoke-OllamaSetup {
    Install-OllamaIfRequested
    $Ollama = Get-OllamaCommand
    if (!$Ollama) {
        Write-Warn "Ollama was not found. Local LLM will work after installing Ollama or any OpenAI-compatible local server."
        return
    }
    if ($StartOllama) {
        if ($DryRun) {
            Write-Step "DryRun: would start Ollama"
        } else {
            & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root "scripts\start_ollama.ps1")
        }
    }
    if ($PullModel) {
        if ($DryRun) {
            Write-Step "DryRun: would run ollama pull $Model"
        } else {
            & $Ollama pull $Model
        }
    }
    if (Test-Ollama) {
        Write-Ok "Ollama endpoint is reachable."
    } else {
        Write-Warn "Ollama endpoint is not currently reachable at http://127.0.0.1:11434."
    }
}

function Write-LauncherInfo {
    if (!$CreateLauncher) {
        return
    }
    $Launcher = Join-Path $Root "MonsteyAI-Launcher.cmd"
    $LauncherPs1 = Join-Path $Root "MonsteyAI-Launcher.ps1"
    if (Test-Path -LiteralPath $Launcher) {
        Write-Ok "Launcher ready: $Launcher"
    } elseif (Test-Path -LiteralPath $LauncherPs1) {
        Write-Ok "Launcher ready: $LauncherPs1"
    } else {
        Write-Warn "Launcher files were not found next to setup.ps1."
    }
}

function New-DesktopShortcut([string]$ResolvedIdaPath) {
    if (!$CreateDesktopShortcut) {
        return
    }
    $Launcher = Join-Path $Root "MonsteyAI-Launcher.cmd"
    if (!(Test-Path -LiteralPath $Launcher)) {
        Write-Warn "Launcher cmd not found, skipping desktop shortcut."
        return
    }
    $Desktop = [Environment]::GetFolderPath("Desktop")
    $ShortcutPath = Join-Path $Desktop "Monstey-AI Launcher.lnk"
    if ($DryRun) {
        Write-Step "DryRun: would create desktop shortcut $ShortcutPath"
        return
    }
    $Shell = New-Object -ComObject WScript.Shell
    $Shortcut = $Shell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = $Launcher
    $Shortcut.WorkingDirectory = $Root
    if ($ResolvedIdaPath) {
        $Shortcut.Arguments = "-IdaPath `"$ResolvedIdaPath`""
    }
    $Shortcut.IconLocation = $ResolvedIdaPath
    $Shortcut.Save()
    Write-Ok "Desktop shortcut created: $ShortcutPath"
}

Write-Step "Root: $Root"
$ResolvedIdaPath = Resolve-IdaExe $IdaPath
if ($ResolvedIdaPath) {
    Write-Ok "IDA detected: $ResolvedIdaPath"
} else {
    Write-Warn "IDA was not auto-detected. User-scope install can still work; pass -IdaPath for install-scope launcher."
}

$InstalledDirs = New-Object System.Collections.Generic.List[string]
if ($InstallScope -in @("User", "Both")) {
    $UserDir = Get-UserPluginsDir
    Invoke-PluginInstall $UserDir
    $InstalledDirs.Add($UserDir) | Out-Null
}
if ($InstallScope -in @("IDA", "Both")) {
    $IdaDir = Get-IdaPluginsDir $ResolvedIdaPath
    if (!$IdaDir) {
        if ($NonInteractive) {
            throw "IDA install-scope requested but IDA path was not found. Pass -IdaPath or -IdaPluginsDir."
        }
        Write-Warn "Skipping IDA install-scope because IDA path/plugins dir was not found."
    } else {
        Invoke-PluginInstall $IdaDir
        $InstalledDirs.Add($IdaDir) | Out-Null
    }
}

Write-PluginConfig
Invoke-OllamaSetup
Write-SetupState $ResolvedIdaPath $InstalledDirs.ToArray()
Write-LauncherInfo
New-DesktopShortcut $ResolvedIdaPath

Write-Host ""
Write-Ok "Setup complete."
Write-Host "Restart IDA, then open Monstey-AI-plugin with Ctrl+Alt+G or Edit > Plugins."
