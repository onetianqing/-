from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass
class ModelResponse:
    model: str
    provider: str
    final_answer: str
    messages: list[dict[str, str]]
    tool_calls: list[dict[str, Any]]
    usage: dict[str, int]
    latency_ms: int
    cost_usd: float
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "provider": self.provider,
            "messages": self.messages,
            "final_answer": self.final_answer,
            "tool_calls": self.tool_calls,
            "usage": self.usage,
            "latency_ms": self.latency_ms,
            "cost_usd": self.cost_usd,
            "error": self.error,
        }


class ModelClientError(RuntimeError):
    pass


def call_model(
    model_config: dict[str, Any],
    messages: list[dict[str, str]],
    temperature: float | None = None,
    max_tokens: int | None = None,
    response_format: dict[str, Any] | None = None,
) -> ModelResponse:
    provider = model_config.get("provider")
    if provider == "local_mock":
        return _call_local_mock(model_config, messages)
    if provider == "openai_compatible":
        return _call_openai_compatible(model_config, messages, temperature, max_tokens, response_format)
    raise ModelClientError(f"Unsupported provider: {provider}")


def _call_openai_compatible(
    model_config: dict[str, Any],
    messages: list[dict[str, str]],
    temperature: float | None,
    max_tokens: int | None,
    response_format: dict[str, Any] | None,
) -> ModelResponse:
    base_url = str(model_config.get("base_url", "")).rstrip("/")
    api_key_env = model_config.get("api_key_env")
    api_key = os.environ.get(str(api_key_env or ""))
    if not base_url:
        raise ModelClientError(f"Model {model_config.get('name')} is missing base_url")
    if not api_key:
        raise ModelClientError(f"Environment variable {api_key_env} is not set")

    payload: dict[str, Any] = {
        "model": model_config.get("model_id"),
        "messages": messages,
        "temperature": temperature if temperature is not None else model_config.get("temperature", 0.2),
        "max_tokens": max_tokens if max_tokens is not None else model_config.get("max_tokens", 4096),
    }
    response_format_policy = str(model_config.get("response_format", "json_object")).lower()
    if response_format and response_format_policy not in {"none", "disabled", "false", "off"}:
        payload["response_format"] = response_format

    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )

    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise ModelClientError(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise ModelClientError(f"Request failed: {exc}") from exc

    latency_ms = int((time.perf_counter() - started) * 1000)
    parsed = json.loads(body)
    final_answer = parsed["choices"][0]["message"].get("content") or ""
    usage = parsed.get("usage") or {}
    normalized_usage = {
        "input_tokens": int(usage.get("prompt_tokens", usage.get("input_tokens", 0)) or 0),
        "output_tokens": int(usage.get("completion_tokens", usage.get("output_tokens", 0)) or 0),
        "total_tokens": int(usage.get("total_tokens", 0) or 0),
    }
    if not normalized_usage["total_tokens"]:
        normalized_usage["total_tokens"] = normalized_usage["input_tokens"] + normalized_usage["output_tokens"]

    cost_usd = estimate_cost_usd(model_config, normalized_usage)
    return ModelResponse(
        model=str(model_config.get("name")),
        provider="openai_compatible",
        final_answer=final_answer,
        messages=messages,
        tool_calls=[],
        usage=normalized_usage,
        latency_ms=latency_ms,
        cost_usd=cost_usd,
    )


def _call_local_mock(model_config: dict[str, Any], messages: list[dict[str, str]]) -> ModelResponse:
    started = time.perf_counter()
    combined = "\n".join(message.get("content", "") for message in messages)
    finding = _mock_finding(combined)
    final_answer = json.dumps({"findings": [finding], "summary": "Local mock audit completed."}, ensure_ascii=False, indent=2)
    latency_ms = int((time.perf_counter() - started) * 1000)
    approx_input = max(1, len(combined) // 4)
    approx_output = max(1, len(final_answer) // 4)
    return ModelResponse(
        model=str(model_config.get("name")),
        provider="local_mock",
        final_answer=final_answer,
        messages=messages,
        tool_calls=[],
        usage={
            "input_tokens": approx_input,
            "output_tokens": approx_output,
            "total_tokens": approx_input + approx_output,
        },
        latency_ms=latency_ms,
        cost_usd=0.0,
    )


def _mock_finding(prompt_text: str) -> dict[str, Any]:
    if "SELECT id, username FROM users" in prompt_text:
        return {
            "type": "SQL Injection",
            "severity": "high",
            "file": "files/app.py",
            "line": 27,
            "function": "login",
            "evidence": "The login handler builds a SELECT statement by concatenating username and password from request.form.",
            "root_cause": "User-controlled username and password are concatenated into a SQL query instead of using parameter binding.",
            "exploit": "Submit username ' OR '1'='1' -- and any password in the local app to bypass the WHERE clause.",
            "fix": "Use sqlite parameter binding, for example execute('SELECT ... WHERE username = ? AND password = ?', (username, password)).",
            "confidence": 0.92,
        }
    if "res.send(`<h1>Search results for: ${q}</h1>`)" in prompt_text:
        return {
            "type": "Cross-Site Scripting",
            "severity": "medium",
            "file": "files/server.js",
            "line": 12,
            "function": "search",
            "evidence": "The q query parameter is interpolated directly into an HTML response.",
            "root_cause": "Untrusted request query data is rendered as HTML without escaping or template autoescape.",
            "exploit": "Use the payload <script>alert(1)</script> by opening /search?q=<script>alert(1)</script> in the local service.",
            "fix": "Escape or encode q before rendering, or use a template engine with autoescape enabled.",
            "confidence": 0.9,
        }
    if "requests.get(target, timeout=3)" in prompt_text:
        return {
            "type": "SSRF",
            "severity": "high",
            "file": "files/app.py",
            "line": 18,
            "function": "fetch_url",
            "evidence": "The url query parameter is passed directly to requests.get.",
            "root_cause": "The server fetches attacker-controlled URLs without scheme, host, or private IP validation.",
            "exploit": "Request /fetch?url=http://127.0.0.1:8000/admin in the local environment to reach internal services.",
            "fix": "Use an allowlist of hosts, reject private and loopback IP ranges after DNS resolution, and restrict schemes.",
            "confidence": 0.9,
        }
    if "subprocess.check_output(command, shell=True" in prompt_text:
        return {
            "type": "Command Injection",
            "severity": "critical",
            "file": "files/app.py",
            "line": 14,
            "function": "ping",
            "evidence": "The host query parameter is concatenated into a shell command executed with shell=True.",
            "root_cause": "Untrusted input reaches the operating system shell without validation or argument separation.",
            "exploit": "Call /ping?host=127.0.0.1;whoami in the local app to append another command.",
            "fix": "Avoid shell=True, pass an argument list to subprocess, and validate host with an allowlist parser.",
            "confidence": 0.93,
        }
    if "send_file(full_path)" in prompt_text:
        return {
            "type": "Path Traversal",
            "severity": "high",
            "file": "files/app.py",
            "line": 15,
            "function": "download",
            "evidence": "The requested file name is joined with a base directory and sent without normalizing or checking the final path.",
            "root_cause": "Attacker-controlled path segments can escape the intended download directory with ../ traversal.",
            "exploit": "Request /download?name=../app.py or another local relative path to read files outside the download directory.",
            "fix": "Resolve the final path and ensure it remains under the base directory before calling send_file.",
            "confidence": 0.9,
        }
    if "SELECT * FROM Users WHERE email = '" in prompt_text:
        return {
            "type": "SQL Injection",
            "severity": "high",
            "file": "files/login.js",
            "line": 16,
            "function": "login",
            "evidence": "The email and password fields are concatenated into a SQL query before database execution.",
            "root_cause": "Untrusted login input is embedded into a SQL statement without parameter binding.",
            "exploit": "Use a payload such as ' OR 1=1-- in the email field in the local login route to alter the WHERE clause.",
            "fix": "Use parameterized queries or ORM bind parameters and avoid string concatenation for authentication queries.",
            "confidence": 0.92,
        }
    if "shell_exec($cmd)" in prompt_text:
        return {
            "type": "Command Injection",
            "severity": "critical",
            "file": "files/vulnerable.php",
            "line": 10,
            "function": "ping_host",
            "evidence": "The ip request parameter is appended to a ping command and passed to shell_exec.",
            "root_cause": "Attacker-controlled input reaches a shell command without validation or argument separation.",
            "exploit": "Submit ip=127.0.0.1;whoami in the local DVWA-style form to append another command.",
            "fix": "Avoid shell execution, validate IP addresses with filter_var, and use an argument array or safe library.",
            "confidence": 0.94,
        }
    if "urllib.parse.unquote(cleaned)" in prompt_text and "Alias-like path mapper" in prompt_text:
        return {
            "type": "Path Traversal",
            "severity": "critical",
            "file": "files/alias_mapper.py",
            "line": 13,
            "function": "map_url_to_file",
            "evidence": "Traversal removal happens before percent-decoding, so encoded dot segments can reappear after validation.",
            "root_cause": "The mapper normalizes and validates the path in the wrong order, allowing encoded ../ segments to escape the document root.",
            "exploit": "Use a payload such as /cgi-bin/.%2e/.%2e/.%2e/etc/passwd, which decodes into ../ traversal and reaches outside the alias directory.",
            "fix": "Decode before normalization, resolve the final path, and require it to remain inside the configured base directory.",
            "confidence": 0.91,
        }
    return {
        "type": "No confirmed vulnerability",
        "severity": "info",
        "file": "",
        "line": None,
        "function": "",
        "evidence": "The mock model only recognizes bundled sample tasks.",
        "root_cause": "",
        "exploit": "",
        "fix": "",
        "confidence": 0.2,
    }


def estimate_cost_usd(model_config: dict[str, Any], usage: dict[str, int]) -> float:
    pricing = model_config.get("pricing") or {}
    try:
        input_price = float(
            pricing.get("usd_per_1m_input_tokens", model_config.get("usd_per_1m_input_tokens", 0)) or 0
        )
        output_price = float(
            pricing.get("usd_per_1m_output_tokens", model_config.get("usd_per_1m_output_tokens", 0)) or 0
        )
    except (TypeError, ValueError):
        return 0.0
    input_tokens = int(usage.get("input_tokens", 0) or 0)
    output_tokens = int(usage.get("output_tokens", 0) or 0)
    return round((input_tokens * input_price + output_tokens * output_price) / 1_000_000, 8)
