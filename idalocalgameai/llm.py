"""OpenAI-compatible local LLM client."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List

from .config import PluginConfig


class LocalLLMError(RuntimeError):
    pass


_OLLAMA_FAILED_START_COOLDOWN_SECONDS = 60.0
_OLLAMA_LAST_START_ATTEMPT = 0.0
_OLLAMA_LAST_START_OK = False


class OpenAICompatClient:
    def __init__(self, cfg: PluginConfig):
        self.cfg = cfg

    def _url(self, path: str) -> str:
        base = self.cfg.active_base_url().rstrip("/")
        return base + path

    def _headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % (self.cfg.active_api_key() or "ollama"),
        }

    def _is_local_ollama_url(self) -> bool:
        try:
            parsed = urllib.parse.urlparse(self.cfg.active_base_url())
            host = parsed.hostname or ""
            return self.cfg.provider == "local" and host in ("127.0.0.1", "localhost", "::1") and parsed.port in (None, 11434)
        except Exception:
            return False

    def _ollama_candidates(self) -> List[str]:
        candidates = [
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Ollama", "ollama.exe"),
            os.path.join(os.environ.get("PROGRAMFILES", ""), "Ollama", "ollama.exe"),
        ]
        return [path for path in candidates if path and os.path.isfile(path)]

    def _try_start_ollama(self) -> bool:
        global _OLLAMA_LAST_START_ATTEMPT, _OLLAMA_LAST_START_OK
        if not self._is_local_ollama_url():
            return False
        now = time.time()
        if _OLLAMA_LAST_START_ATTEMPT and not _OLLAMA_LAST_START_OK:
            if now - _OLLAMA_LAST_START_ATTEMPT < _OLLAMA_FAILED_START_COOLDOWN_SECONDS:
                return False
        _OLLAMA_LAST_START_ATTEMPT = now
        _OLLAMA_LAST_START_OK = False
        candidates = self._ollama_candidates()
        if not candidates:
            return False
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        for path in candidates:
            try:
                subprocess.Popen([path, "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags)
                for _ in range(20):
                    time.sleep(0.5)
                    try:
                        req = urllib.request.Request("http://127.0.0.1:11434/api/version", method="GET")
                        with urllib.request.urlopen(req, timeout=2):
                            _OLLAMA_LAST_START_OK = True
                            return True
                    except Exception:
                        continue
            except Exception:
                continue
        return False

    def _post_chat(self, data: bytes, timeout: int = None) -> str:
        req = urllib.request.Request(self._url("/chat/completions"), data=data, headers=self._headers(), method="POST")
        with urllib.request.urlopen(req, timeout=timeout or self.cfg.timeout_seconds) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def _is_timeout(self, exc: Exception) -> bool:
        text = str(exc or "").lower()
        return isinstance(exc, (TimeoutError, socket.timeout)) or "timed out" in text or "timeout" in text

    def _timeout_message(self, timeout: int = None) -> str:
        seconds = int(timeout or self.cfg.timeout_seconds)
        return (
            "Local model '%s' timed out after %ds at %s. "
            "For quick ASM/function triage use Fast/Balanced with qwen2.5-coder:7b/14b, "
            "or raise Analysis timeout / use Deep when you really need the heavy model."
            % (self.cfg.active_model(), seconds, self.cfg.active_base_url())
        )

    def _http_error_message(self, code: int, detail: str) -> str:
        detail = str(detail or "")
        message = "LLM HTTP %s: %s" % (code, detail[:900])
        if self.cfg.provider == "gemini" and code == 429:
            hint = (
                "\n\nGemini quota note: this API key/project is accepted, but the selected model has no remaining API quota. "
                "If the detail mentions limit: 0 for gemini-2.5-pro, enable Gemini API billing/quota in Google AI Studio or switch to "
                "Gemini 2.5 Flash / Gemini 3.5 Flash in the plugin settings."
            )
            if "gemini-2.5-pro" in detail or "quota" in detail.lower():
                message += hint
        elif self.cfg.provider == "gemini" and code in (400, 404):
            message += (
                "\n\nGemini provider note: check the model name, API key, and base URL. "
                "The expected OpenAI-compatible base URL is https://generativelanguage.googleapis.com/v1beta/openai"
            )
        elif self.cfg.provider == "gemini" and code in (401, 403):
            message += "\n\nGemini auth note: the API key was rejected or the project is not allowed to use the Gemini API."
        return message

    def chat(self, messages: List[Dict[str, str]], max_tokens: int = 2200, json_mode: bool = False, timeout: int = None) -> str:
        payload: Dict[str, Any] = {
            "model": self.cfg.active_model(),
            "messages": messages,
            "temperature": self.cfg.temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        data = json.dumps(payload).encode("utf-8")
        try:
            body = self._post_chat(data, timeout=timeout)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            if json_mode and exc.code in (400, 404, 422):
                payload.pop("response_format", None)
                try:
                    body = self._post_chat(json.dumps(payload).encode("utf-8"), timeout=timeout)
                except urllib.error.HTTPError as retry_exc:
                    retry_detail = retry_exc.read().decode("utf-8", errors="replace")
                    raise LocalLLMError(self._http_error_message(retry_exc.code, retry_detail))
                except Exception as retry_exc:
                    raise LocalLLMError("LLM JSON-mode fallback failed: %s" % retry_exc)
            else:
                raise LocalLLMError(self._http_error_message(exc.code, detail))
        except Exception as exc:
            if self.cfg.provider == "local" and self._is_timeout(exc):
                raise LocalLLMError(self._timeout_message(timeout))
            if self._try_start_ollama():
                try:
                    body = self._post_chat(data, timeout=timeout)
                except Exception as retry_exc:
                    if self._is_timeout(retry_exc):
                        raise LocalLLMError(self._timeout_message(timeout))
                    raise LocalLLMError("Local LLM was started, but the request still failed: %s" % retry_exc)
            else:
                raise LocalLLMError("Cannot reach %s provider at %s: %s" % (
                    self.cfg.active_provider_label(),
                    self.cfg.active_base_url(),
                    exc,
                ))

        try:
            obj = json.loads(body)
            return obj["choices"][0]["message"]["content"]
        except Exception as exc:
            raise LocalLLMError("Unexpected LLM response: %s" % exc)

    def test(self) -> str:
        return self.chat(
            [
                {"role": "system", "content": "Return only JSON."},
                {"role": "user", "content": '{"ping":"monstey-ai-plugin"}'},
            ],
            max_tokens=80,
        )
