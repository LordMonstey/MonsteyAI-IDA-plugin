param(
    [ValidateSet("Core", "Advanced", "Full")]
    [string]$Tier = "Core",

    [string]$PythonPath = "",
    [string]$VenvDir = "",

    [switch]$Strict,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

function Write-Step([string]$Message) {
    Write-Host "[Monstey toolchain] $Message" -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warn([string]$Message) {
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Resolve-Python([string]$Hint) {
    if ($Hint -and (Test-Path -LiteralPath $Hint -PathType Leaf)) {
        return (Resolve-Path -LiteralPath $Hint).Path
    }
    foreach ($Command in @("python", "py")) {
        $Found = Get-Command $Command -ErrorAction SilentlyContinue
        if ($Found -and $Found.Source) {
            return $Found.Source
        }
    }
    return ""
}

function Get-ToolchainRoot {
    $Path = Join-Path $env:USERPROFILE ".monstey-ai-plugin\toolchain"
    if (!$DryRun) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
    return $Path
}

function Invoke-PipInstall([string]$PythonExe, [string]$Requirement) {
    Write-Step "Installing $Requirement"
    if ($DryRun) {
        return @{ requirement = $Requirement; ok = $true; dry_run = $true }
    }
    try {
        & $PythonExe -m pip install $Requirement
        if ($LASTEXITCODE -ne 0) {
            throw "pip exited with code $LASTEXITCODE"
        }
        return @{ requirement = $Requirement; ok = $true }
    } catch {
        $Message = $_.Exception.Message
        if ($Strict) {
            throw
        }
        Write-Warn "Optional dependency failed: $Requirement ($Message)"
        return @{ requirement = $Requirement; ok = $false; error = $Message }
    }
}

function Get-Requirements([string]$Path) {
    if (!(Test-Path -LiteralPath $Path)) {
        return @()
    }
    $Items = @()
    foreach ($Line in Get-Content -LiteralPath $Path) {
        $Trimmed = $Line.Trim()
        if (!$Trimmed -or $Trimmed.StartsWith("#")) {
            continue
        }
        $Items += $Trimmed
    }
    return $Items
}

$ToolchainRoot = Get-ToolchainRoot
if (!$VenvDir) {
    $VenvDir = Join-Path $ToolchainRoot ".venv"
}

$Python = Resolve-Python $PythonPath
if (!$Python) {
    throw "Python was not found. Install Python 3.10+ or pass -PythonPath."
}

Write-Step "Root: $Root"
Write-Step "Tier: $Tier"
Write-Step "Python: $Python"
Write-Step "Venv: $VenvDir"

if (!(Test-Path -LiteralPath $VenvDir)) {
    if ($DryRun) {
        Write-Step "DryRun: would create venv at $VenvDir"
    } else {
        & $Python -m venv $VenvDir
        if ($LASTEXITCODE -ne 0) {
            throw "venv creation failed with code $LASTEXITCODE"
        }
    }
}

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
if (!(Test-Path -LiteralPath $VenvPython) -and !$DryRun) {
    throw "Venv python not found: $VenvPython"
}
if ($DryRun) {
    $VenvPython = Join-Path $VenvDir "Scripts\python.exe"
}

if (!$DryRun) {
    & $VenvPython -m pip install --upgrade pip setuptools wheel
}

$CoreReq = Join-Path $Root "requirements-toolchain-core.txt"
$AdvancedReq = Join-Path $Root "requirements-toolchain-advanced.txt"
$Requirements = @()
$Requirements += Get-Requirements $CoreReq
if ($Tier -in @("Advanced", "Full")) {
    $Requirements += Get-Requirements $AdvancedReq
}

$Results = @()
foreach ($Requirement in $Requirements) {
    $Results += Invoke-PipInstall $VenvPython $Requirement
}

$SidecarScript = Join-Path $Root "idalocalgameai\toolchain_sidecar.py"
$Check = ""
if ((Test-Path -LiteralPath $SidecarScript) -and !$DryRun) {
    try {
        $Check = (& $VenvPython $SidecarScript check | Out-String).Trim()
    } catch {
        Write-Warn "Toolchain check failed after install: $($_.Exception.Message)"
    }
}

$StatePath = Join-Path $ToolchainRoot "toolchain_state.json"
$State = [ordered]@{
    version = 1
    tier = $Tier
    python = $VenvPython
    venv = $VenvDir
    results = $Results
    sidecar_script = $SidecarScript
    check = $Check
    updated_at = (Get-Date).ToString("s")
}
if ($DryRun) {
    Write-Step "DryRun: would write toolchain state to $StatePath"
} else {
    $State | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $StatePath -Encoding UTF8
    Write-Ok "Toolchain state written: $StatePath"
}

Write-Ok "Toolchain setup complete."
Write-Host "Use the plugin Integrations tab > Toolchain Check to verify detected libraries."
