# Contributing

Thanks for helping improve Monstey-AI-plugin.

## Development Setup

1. Clone the repository.
2. Run the plug-and-play setup:

```powershell
.\setup.cmd -InstallScope User -ConfigureLLM -CreateLauncher
```

3. Restart IDA and open `Monstey-AI-plugin` with `Ctrl+Alt+G`.

## Validation

Before opening a PR, run:

```powershell
python -m py_compile (Get-ChildItem -Path .\idalocalgameai -Recurse -Filter *.py | ForEach-Object { $_.FullName })
powershell -ExecutionPolicy Bypass -File .\setup.ps1 -DryRun -InstallScope User -ConfigureLLM -CreateLauncher
powershell -ExecutionPolicy Bypass -File .\scripts\package_release.ps1
```

## Useful Issue Data

When reporting setup or provider problems, paste the output of:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check_environment.ps1 -IdaPath "C:\Path\To\ida.exe"
```

Do not upload proprietary dumps, IDBs, API keys, private symbols, or game data.

## Pull Request Style

- Keep changes scoped.
- Prefer deterministic local analysis before adding more LLM calls.
- Keep UI readable inside IDA: short labels, copyable output, bounded panels, and useful colors.
- Include validation notes in the PR body.
