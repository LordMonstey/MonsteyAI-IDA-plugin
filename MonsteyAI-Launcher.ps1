param(
    [string]$IdaPath = "",
    [string]$InputFile = "",
    [switch]$SkipOllama,
    [switch]$WaitForIDA
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Step([string]$Message) {
    Write-Host "[Monstey launcher] $Message" -ForegroundColor Cyan
}

function Write-Warn([string]$Message) {
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Test-File([string]$Path) {
    return [bool]($Path -and (Test-Path -LiteralPath $Path -PathType Leaf))
}

function Get-StateIdaPath {
    $StatePath = Join-Path $env:USERPROFILE ".monstey-ai-plugin\setup_state.json"
    if (!(Test-Path -LiteralPath $StatePath)) {
        return ""
    }
    try {
        $State = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
        if (Test-File $State.ida_path) {
            return $State.ida_path
        }
    } catch {
    }
    return ""
}

function Resolve-IdaExe([string]$Hint) {
    foreach ($Candidate in @($Hint, (Get-StateIdaPath))) {
        if (Test-File $Candidate) {
            return (Resolve-Path -LiteralPath $Candidate).Path
        }
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

function Start-LocalBackend {
    if ($SkipOllama) {
        return
    }
    $Script = Join-Path $Root "scripts\start_ollama.ps1"
    if (!(Test-Path -LiteralPath $Script)) {
        Write-Warn "start_ollama.ps1 not found; skipping local backend startup."
        return
    }
    try {
        & powershell -NoProfile -ExecutionPolicy Bypass -File $Script -TimeoutSeconds 20
    } catch {
        Write-Warn "Local backend was not started: $($_.Exception.Message)"
    }
}

Start-LocalBackend

$ResolvedIda = Resolve-IdaExe $IdaPath
if (!$ResolvedIda) {
    throw "IDA executable not found. Run setup.ps1 -IdaPath `"C:\Path\To\ida.exe`" or pass -IdaPath to this launcher."
}

$ArgsList = @()
if ($InputFile) {
    $ArgsList += $InputFile
}

Write-Step "Launching IDA: $ResolvedIda"
if ($ArgsList.Count -gt 0) {
    Write-Step "Input: $InputFile"
}

$Process = Start-Process -FilePath $ResolvedIda -ArgumentList $ArgsList -PassThru
if ($WaitForIDA) {
    $Process.WaitForExit()
}
