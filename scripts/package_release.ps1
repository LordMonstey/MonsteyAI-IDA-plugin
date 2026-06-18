param(
    [string]$Version = "",
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

if (!$Version) {
    $InitPath = Join-Path $Root "idalocalgameai\__init__.py"
    $InitText = Get-Content -LiteralPath $InitPath -Raw
    if ($InitText -match 'PLUGIN_VERSION\s*=\s*"([^"]+)"') {
        $Version = $Matches[1]
    } else {
        $Version = "dev"
    }
}

if (!$OutputDir) {
    $OutputDir = Split-Path -Parent $Root
}

$PackageName = "Monstey-AI-plugin-v$Version"
$StageRoot = Join-Path $env:TEMP ("monstey-ai-plugin-package-" + [guid]::NewGuid().ToString("N"))
$StageDir = Join-Path $StageRoot $PackageName
$ZipPath = Join-Path $OutputDir ($PackageName + ".zip")

New-Item -ItemType Directory -Force -Path $StageDir | Out-Null

$ExcludeDirs = @(".git", "__pycache__", ".pytest_cache", ".mypy_cache")
$ExcludeFiles = @("*.pyc", "*.pyo", "*.zip")

function Test-ExcludedPath([string]$Path) {
    $Parts = $Path -split '[\\/]'
    foreach ($Dir in $ExcludeDirs) {
        if ($Parts -contains $Dir) {
            return $true
        }
    }
    foreach ($Pattern in $ExcludeFiles) {
        if ((Split-Path -Leaf $Path) -like $Pattern) {
            return $true
        }
    }
    return $false
}

Get-ChildItem -LiteralPath $Root -Recurse -File -Force | ForEach-Object {
    if (Test-ExcludedPath $_.FullName) {
        return
    }
    $RelativePath = $_.FullName.Substring($Root.Length).TrimStart([char[]]@("\", "/"))
    $Destination = Join-Path $StageDir $RelativePath
    $DestinationDir = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Force -Path $DestinationDir | Out-Null
    Copy-Item -LiteralPath $_.FullName -Destination $Destination -Force
}

if (Test-Path -LiteralPath $ZipPath) {
    Remove-Item -LiteralPath $ZipPath -Force
}

Compress-Archive -LiteralPath $StageDir -DestinationPath $ZipPath -Force
Remove-Item -LiteralPath $StageRoot -Recurse -Force

Write-Host "Release package created:"
Write-Host "  $ZipPath"
