param(
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"

function Test-Ollama {
    try {
        Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/version" -TimeoutSec 2 | Out-Null
        return $true
    } catch {
        return $false
    }
}

if (Test-Ollama) {
    Write-Host "Ollama is already running at http://127.0.0.1:11434"
    exit 0
}

$Ollama = Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama.exe"
if (!(Test-Path -LiteralPath $Ollama)) {
    $Cmd = Get-Command ollama -ErrorAction SilentlyContinue
    if ($Cmd) {
        $Ollama = $Cmd.Source
    }
}

if (!(Test-Path -LiteralPath $Ollama)) {
    throw "Cannot find ollama.exe. Install Ollama first."
}

Start-Process -FilePath $Ollama -ArgumentList "serve" -WindowStyle Hidden

$Deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while ((Get-Date) -lt $Deadline) {
    Start-Sleep -Milliseconds 500
    if (Test-Ollama) {
        Write-Host "Ollama is running at http://127.0.0.1:11434"
        exit 0
    }
}

throw "Ollama did not answer within $TimeoutSeconds seconds."
