param(
    [string]$IdaPath = ""
)

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

function Test-Endpoint([string]$Url) {
    try {
        Invoke-RestMethod -Uri $Url -TimeoutSec 2 | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Resolve-IdaExe([string]$Hint) {
    if ($Hint -and (Test-Path -LiteralPath $Hint -PathType Leaf)) {
        return (Resolve-Path -LiteralPath $Hint).Path
    }
    foreach ($Command in @("ida.exe", "ida64.exe")) {
        $Found = Get-Command $Command -ErrorAction SilentlyContinue
        if ($Found) {
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
            if ($Match) {
                return $Match.FullName
            }
        } catch {
        }
    }
    return ""
}

$UserPlugins = Join-Path $env:APPDATA "Hex-Rays\IDA Pro\plugins"
$IdaExe = Resolve-IdaExe $IdaPath
$IdaPlugins = if ($IdaExe) { Join-Path (Split-Path -Parent $IdaExe) "plugins" } else { "" }
$ConfigPath = Join-Path $env:USERPROFILE ".monstey-ai-plugin\config.json"
$StatePath = Join-Path $env:USERPROFILE ".monstey-ai-plugin\setup_state.json"
$OllamaCmd = Get-Command ollama -ErrorAction SilentlyContinue
$IdaPySwitch = if ($IdaExe) { Join-Path (Split-Path -Parent $IdaExe) "idapyswitch.exe" } else { "" }

$Rows = [ordered]@{
    "Package root" = $Root
    "IDA executable" = if ($IdaExe) { $IdaExe } else { "not found" }
    "User plugins dir" = $UserPlugins
    "User plugin installed" = Test-Path -LiteralPath (Join-Path $UserPlugins "Monstey-AI-plugin")
    "IDA plugins dir" = if ($IdaPlugins) { $IdaPlugins } else { "not found" }
    "IDA-scope plugin installed" = if ($IdaPlugins) { Test-Path -LiteralPath (Join-Path $IdaPlugins "Monstey-AI-plugin") } else { $false }
    "idapyswitch available" = if ($IdaPySwitch) { Test-Path -LiteralPath $IdaPySwitch } else { $false }
    "Config exists" = Test-Path -LiteralPath $ConfigPath
    "Setup state exists" = Test-Path -LiteralPath $StatePath
    "Ollama command" = if ($OllamaCmd) { $OllamaCmd.Source } else { "not found" }
    "Ollama API reachable" = Test-Endpoint "http://127.0.0.1:11434/api/version"
    "OpenAI-compatible endpoint reachable" = Test-Endpoint "http://127.0.0.1:11434/v1/models"
    "PowerShell" = $PSVersionTable.PSVersion.ToString()
}

Write-Host "MonsteyAI-IDA-plugin environment check"
Write-Host "=================================="
foreach ($Key in $Rows.Keys) {
    Write-Host ("{0,-38} {1}" -f ($Key + ":"), $Rows[$Key])
}
