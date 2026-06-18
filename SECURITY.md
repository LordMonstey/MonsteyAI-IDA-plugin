# Security Policy

## Reporting

Please report security-sensitive issues privately when possible. If you use a public issue, remove:

- API keys or tokens;
- proprietary dumps, IDBs, symbols, or binaries;
- private game/project names when disclosure is not intended;
- local paths that reveal personal information.

## Data Handling

Monstey-AI-plugin is local-first by design. Local provider mode sends analysis prompts only to the configured OpenAI-compatible endpoint, usually `127.0.0.1`.

Hosted provider mode sends the selected bounded analysis context to the configured hosted API. Review the provider setting before analyzing private binaries.

## Recommended Defaults

- Use `Local / Ollama` for private lab work.
- Keep `Global string scan` disabled unless you need it.
- Use `Preview Focus` before sending context to an LLM.
- Do not paste secrets into Dump Context, Evidence Sources, Pseudo Diff, or Action Lab.
