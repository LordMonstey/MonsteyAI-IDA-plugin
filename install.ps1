param(
    [string]$IdaPluginsDir = "$env:APPDATA\Hex-Rays\IDA Pro\plugins"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

if (!(Test-Path -LiteralPath $Root)) {
    throw "Cannot locate plugin root."
}

New-Item -ItemType Directory -Force -Path $IdaPluginsDir | Out-Null

$ResolvedPluginsDir = (Resolve-Path -LiteralPath $IdaPluginsDir).Path
$PluginTarget = Join-Path $IdaPluginsDir "Monstey-AI-plugin"
$LegacyPluginTarget = Join-Path $IdaPluginsDir "ida-local-game-ai"
$RootPackageTarget = Join-Path $IdaPluginsDir "idalocalgameai"
$RootEntryTarget = Join-Path $IdaPluginsDir "idalocalgameai_plugin.py"
$DiagTarget = Join-Path $IdaPluginsDir "idalocalgameai_diag.py"
$LegacyManifestTarget = Join-Path $IdaPluginsDir "ida-local-game-ai.ida-plugin.json"
$ResolvedPackageParent = Split-Path -Parent $PluginTarget

if ((Resolve-Path -LiteralPath $ResolvedPackageParent).Path -ne $ResolvedPluginsDir) {
    throw "Refusing to install outside the requested IDA plugins directory."
}

foreach ($OldPath in @($PluginTarget, $LegacyPluginTarget, $RootPackageTarget, $RootEntryTarget, $DiagTarget, $LegacyManifestTarget)) {
    if (Test-Path -LiteralPath $OldPath) {
        Remove-Item -LiteralPath $OldPath -Recurse -Force
    }
}

New-Item -ItemType Directory -Force -Path $PluginTarget | Out-Null
Copy-Item -LiteralPath (Join-Path $Root "ida-plugin.json") -Destination (Join-Path $PluginTarget "ida-plugin.json") -Force
Copy-Item -LiteralPath (Join-Path $Root "idalocalgameai_plugin.py") -Destination (Join-Path $PluginTarget "idalocalgameai_plugin.py") -Force
Copy-Item -LiteralPath (Join-Path $Root "idalocalgameai") -Destination (Join-Path $PluginTarget "idalocalgameai") -Recurse
Copy-Item -LiteralPath (Join-Path $Root "README.md") -Destination (Join-Path $PluginTarget "README.md") -Force
Copy-Item -LiteralPath (Join-Path $Root "docs") -Destination (Join-Path $PluginTarget "docs") -Recurse
Copy-Item -LiteralPath (Join-Path $Root "scripts") -Destination (Join-Path $PluginTarget "scripts") -Recurse
foreach ($Req in @("requirements.txt", "requirements-toolchain-core.txt", "requirements-toolchain-advanced.txt")) {
    $ReqPath = Join-Path $Root $Req
    if (Test-Path -LiteralPath $ReqPath) {
        Copy-Item -LiteralPath $ReqPath -Destination (Join-Path $PluginTarget $Req) -Force
    }
}
foreach ($Helper in @("setup.ps1", "setup.cmd", "MonsteyAI-Launcher.ps1", "MonsteyAI-Launcher.cmd")) {
    $HelperPath = Join-Path $Root $Helper
    if (Test-Path -LiteralPath $HelperPath) {
        Copy-Item -LiteralPath $HelperPath -Destination (Join-Path $PluginTarget $Helper) -Force
    }
}

# Compatibility path for IDA builds that enumerate only root-level plugin files
# or rely on plugins.cfg entries.
Copy-Item -LiteralPath (Join-Path $Root "idalocalgameai_plugin.py") -Destination $RootEntryTarget -Force
Copy-Item -LiteralPath (Join-Path $Root "idalocalgameai") -Destination $RootPackageTarget -Recurse
Copy-Item -LiteralPath (Join-Path $Root "idalocalgameai_diag.py") -Destination $DiagTarget -Force

$PluginsCfg = Join-Path $IdaPluginsDir "plugins.cfg"
if (Test-Path -LiteralPath $PluginsCfg) {
    $CfgText = [System.IO.File]::ReadAllText($PluginsCfg)
    $Lines = $CfgText -split "\r?\n" | Where-Object {
        $_ -notmatch "idalocalgameai_plugin\.py" -and $_ -notmatch "idalocalgameai_diag\.py"
    }
    $NewText = ($Lines -join "`r`n").TrimEnd() + "`r`n`r`nMonsteyAI_IDA_plugin             idalocalgameai_plugin.py Ctrl-Alt-G 0 GUI`r`nAI_Plugin_Diagnostic             idalocalgameai_diag.py Ctrl-Alt-D 0 GUI`r`n"
    [System.IO.File]::WriteAllText($PluginsCfg, $NewText)
}

Write-Host "Installed MonsteyAI-IDA-plugin to:"
Write-Host "  $PluginTarget"
Write-Host "  $RootEntryTarget"
Write-Host "  $DiagTarget"
Write-Host ""
Write-Host "Restart IDA, then use Ctrl+Alt+G or Edit > Plugins > MonsteyAI-IDA-plugin."
