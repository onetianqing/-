from __future__ import annotations

from pathlib import Path
from typing import Any


def load_yaml(path: Path) -> dict[str, Any]:
    """Load YAML with PyYAML when available, falling back to a small subset parser."""
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore

        loaded = yaml.safe_load(text)
        return loaded or {}
    except ModuleNotFoundError:
        return _parse_simple_yaml(text)


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if value == "":
        return ""
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    if value.lower() == "null":
        return None
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1]
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Parse the limited YAML shape used by this project config."""
    root: dict[str, Any] = {}
    lines = [line.rstrip() for line in text.splitlines()]
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        if not raw.startswith(" ") and stripped.endswith(":"):
            key = stripped[:-1]
            next_line = _next_non_empty(lines, i + 1)
            if next_line is not None and next_line.lstrip().startswith("- "):
                items: list[Any] = []
                i += 1
                current: dict[str, Any] | None = None
                while i < len(lines):
                    line = lines[i]
                    if line and not line.startswith(" "):
                        break
                    s = line.strip()
                    if not s:
                        i += 1
                        continue
                    if s.startswith("- "):
                        if current is not None:
                            items.append(current)
                        current = {}
                        rest = s[2:]
                        if rest:
                            k, v = rest.split(":", 1)
                            current[k.strip()] = _parse_scalar(v)
                    elif current is not None and ":" in s:
                        k, v = s.split(":", 1)
                        current[k.strip()] = _parse_scalar(v)
                    i += 1
                if current is not None:
                    items.append(current)
                root[key] = items
                continue
            nested: dict[str, Any] = {}
            i += 1
            while i < len(lines):
                line = lines[i]
                if line and not line.startswith(" "):
                    break
                s = line.strip()
                if not s:
                    i += 1
                    continue
                if ":" in s:
                    k, v = s.split(":", 1)
                    if v.strip() == "":
                        values: list[Any] = []
                        i += 1
                        while i < len(lines):
                            child = lines[i]
                            if not child.startswith("    "):
                                break
                            child_s = child.strip()
                            if child_s.startswith("- "):
                                values.append(_parse_scalar(child_s[2:]))
                            i += 1
                        nested[k.strip()] = values
                        continue
                    nested[k.strip()] = _parse_scalar(v)
                i += 1
            root[key] = nested
            continue
        i += 1
    return root


def _next_non_empty(lines: list[str], start: int) -> str | None:
    for line in lines[start:]:
        if line.strip():
            return line
    return None
