#!/usr/bin/env python3
"""Test a local OpenAI-compatible LLM endpoint outside IDA."""

from __future__ import annotations

import argparse
import json
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:11434/v1")
    parser.add_argument("--model", default="qwen3-coder:30b")
    parser.add_argument("--api-key", default="ollama")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()

    payload = {
        "model": args.model,
        "messages": [
            {"role": "system", "content": "Return only JSON."},
            {"role": "user", "content": '{"ping":"monstey-ai-plugin"}'},
        ],
        "temperature": 0.1,
        "max_tokens": 80,
        "stream": False,
    }
    req = urllib.request.Request(
        args.base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % args.api_key,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=args.timeout) as resp:
        print(resp.read().decode("utf-8", errors="replace"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
