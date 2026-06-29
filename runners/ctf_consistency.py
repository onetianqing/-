from __future__ import annotations

import base64
import binascii
import codecs
import re
from pathlib import Path
from typing import Any

from runners.validate_types import Finding


FLAG_PATTERN = re.compile(r"[A-Za-z0-9_]+\{[^{}\s]{1,200}\}")
DETERMINISTIC_TAGS = {"base64", "hex", "rot13", "morse"}
MORSE_TABLE = {
    ".-": "A",
    "-...": "B",
    "-.-.": "C",
    "-..": "D",
    ".": "E",
    "..-.": "F",
    "--.": "G",
    "....": "H",
    "..": "I",
    ".---": "J",
    "-.-": "K",
    ".-..": "L",
    "--": "M",
    "-.": "N",
    "---": "O",
    ".--.": "P",
    "--.-": "Q",
    ".-.": "R",
    "...": "S",
    "-": "T",
    "..-": "U",
    "...-": "V",
    ".--": "W",
    "-..-": "X",
    "-.--": "Y",
    "--..": "Z",
    "-----": "0",
    ".----": "1",
    "..---": "2",
    "...--": "3",
    "....-": "4",
    ".....": "5",
    "-....": "6",
    "--...": "7",
    "---..": "8",
    "----.": "9",
}


def validate_ctf_artifact_consistency(task_dir: Path, metadata: dict[str, Any]) -> list[Finding]:
    task_id = str(metadata.get("id") or task_dir.name)
    if metadata.get("category") != "ctf":
        return []

    check_types = configured_check_types(metadata)
    if not check_types:
        return []

    expected_flags = normalized_expected_flags(metadata)
    if not expected_flags:
        return []

    candidates: set[str] = set()
    for relative in metadata.get("files", []):
        artifact_path = task_dir / str(relative)
        if not artifact_path.exists() or artifact_path.stat().st_size > 1024 * 1024:
            continue
        try:
            artifact = artifact_path.read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            continue
        candidates.update(decode_candidates(artifact, check_types))

    if not candidates:
        return [
            finding(
                "warning",
                task_id,
                f"CTF deterministic consistency check found no decodable flag candidate for: {', '.join(sorted(check_types))}",
            )
        ]

    normalized_candidates = {_normalize_flag(candidate) for candidate in candidates}
    if expected_flags & normalized_candidates:
        return []

    preview = ", ".join(sorted(candidates)[:5])
    return [
        finding(
            "error",
            task_id,
            f"CTF artifact decodes to [{preview}], but none match expected.flag or expected.accepted_flags.",
        )
    ]


def configured_check_types(metadata: dict[str, Any]) -> set[str]:
    explicit = metadata.get("consistency_checks")
    if isinstance(explicit, list):
        return {str(item).strip().lower() for item in explicit if str(item).strip().lower() in DETERMINISTIC_TAGS}
    tags = {str(tag).strip().lower() for tag in metadata.get("tags", [])}
    return tags & DETERMINISTIC_TAGS


def normalized_expected_flags(metadata: dict[str, Any]) -> set[str]:
    expected = metadata.get("expected", {}) if isinstance(metadata.get("expected"), dict) else {}
    flags = [str(expected.get("flag") or "").strip()]
    accepted = expected.get("accepted_flags", [])
    if isinstance(accepted, list):
        flags.extend(str(flag).strip() for flag in accepted if str(flag).strip())
    return {_normalize_flag(flag) for flag in flags if flag}


def decode_candidates(artifact: str, check_types: set[str]) -> set[str]:
    candidates: set[str] = set()
    if "base64" in check_types:
        for decoded in _decode_base64_values(artifact):
            candidates.update(extract_flags(decoded))
    if "hex" in check_types:
        candidates.update(extract_flags(_decode_hex(artifact)))
    if "rot13" in check_types:
        candidates.update(extract_flags(codecs.decode(artifact, "rot_13")))
    if "morse" in check_types:
        decoded = _decode_morse(artifact)
        candidates.update(extract_flags(decoded))
        candidates.update(flags_from_morse_phrase(decoded))
    return candidates


def extract_flags(text: str) -> set[str]:
    return {match.group(0) for match in FLAG_PATTERN.finditer(text or "")}


def flags_from_morse_phrase(text: str) -> set[str]:
    normalized = re.sub(r"\s+", " ", text.strip())
    match = re.fullmatch(r"FLAG\s+(.+)", normalized, flags=re.IGNORECASE)
    if not match:
        return set()
    body = re.sub(r"[^A-Za-z0-9]+", "_", match.group(1).strip()).strip("_")
    if not body:
        return set()
    return {f"flag{{{body}}}", f"flag{{{body.lower()}}}"}


def _decode_base64_values(text: str) -> set[str]:
    values: set[str] = set()
    compact = re.sub(r"\s+", "", text)
    for candidate in [compact, *re.findall(r"[A-Za-z0-9+/]{8,}={0,2}", text)]:
        if len(candidate) % 4:
            continue
        try:
            values.add(base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore"))
        except (binascii.Error, ValueError):
            continue
    return values


def _decode_hex(text: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", text)
    if not compact or len(compact) % 2:
        return ""
    try:
        return bytes.fromhex(compact).decode("utf-8", errors="ignore")
    except ValueError:
        return ""


def _decode_morse(text: str) -> str:
    words: list[str] = []
    for raw_word in re.split(r"\s*/\s*|\s{2,}", text.strip()):
        letters = []
        for token in raw_word.split():
            letters.append(MORSE_TABLE.get(token, ""))
        if letters:
            words.append("".join(letters))
    return " ".join(words)


def _normalize_flag(flag: str) -> str:
    return re.sub(r"\s+", "", flag.strip())


def finding(level: str, target: str, message: str) -> Finding:
    return {"level": level, "target": target, "message": message}
