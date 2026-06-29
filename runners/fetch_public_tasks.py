from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


SUPPORTED_REGISTRY_VERSIONS = {1}
DEFAULT_USER_AGENT = "security-model-eval-platform/0.32 (+local research staging)"


@dataclass
class PageInfo:
    url: str
    title: str
    links: list[tuple[str, str]]


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title_parts: list[str] = []
        self.in_title = False
        self.links: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "title":
            self.in_title = True
        if tag.lower() == "a":
            attrs_map = {name.lower(): value for name, value in attrs}
            href = attrs_map.get("href")
            if href:
                self._current_href = href
                self._current_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False
        if tag.lower() == "a" and self._current_href:
            text = normalize_space(" ".join(self._current_text))
            self.links.append((self._current_href, text))
            self._current_href = None
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
        if self._current_href:
            self._current_text.append(data)

    @property
    def title(self) -> str:
        return normalize_space(" ".join(self.title_parts))


def main() -> int:
    args = parse_args()
    try:
        registry = load_registry(PROJECT_ROOT / args.registry)
        selected_sources = select_sources(registry, args.source_id)
    except ValueError as exc:
        print(f"Source registry error: {exc}", file=sys.stderr)
        return 2

    candidates = discover_candidates(selected_sources, args)
    output = build_output(args.registry, selected_sources, candidates, offline=args.offline)
    print_summary(output, dry_run=args.dry_run)

    if args.dry_run:
        return 0

    output_path = PROJECT_ROOT / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Staging candidates written: {output_path}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch public source references into a staging candidate list.")
    parser.add_argument("--registry", default="docs/examples/source_registry.json", help="Source registry JSON path relative to project root.")
    parser.add_argument("--source-id", default="all", help="Comma-separated source ids, or all enabled sources.")
    parser.add_argument("--output", default="staging/source_candidates.json", help="Output staging JSON path relative to project root.")
    parser.add_argument("--max-links", type=int, default=50, help="Maximum candidate links per fetched seed URL.")
    parser.add_argument("--timeout", type=int, default=20, help="HTTP timeout seconds.")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="HTTP User-Agent.")
    parser.add_argument("--offline", action="store_true", help="Do not make network requests; emit one candidate per source/seed URL.")
    parser.add_argument("--dry-run", action="store_true", help="Print summary without writing the staging file.")
    parser.add_argument("--include-external", action="store_true", help="Keep links outside the seed URL host.")
    return parser.parse_args()


def load_registry(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ValueError(f"registry not found: {path}")
    try:
        registry = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"registry is not valid JSON: {exc}") from exc
    if not isinstance(registry, dict):
        raise ValueError("registry root must be an object.")
    version = int(registry.get("schema_version") or 1)
    if version not in SUPPORTED_REGISTRY_VERSIONS:
        raise ValueError(f"unsupported schema_version: {version}")
    sources = registry.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("registry.sources must be a non-empty list.")
    return registry


def select_sources(registry: dict[str, Any], selector: str) -> list[dict[str, Any]]:
    sources = [source for source in registry.get("sources", []) if isinstance(source, dict)]
    if selector == "all":
        selected = [source for source in sources if source.get("enabled", True)]
    else:
        requested = {item.strip() for item in selector.split(",") if item.strip()}
        selected = [source for source in sources if source.get("id") in requested]
    valid: list[dict[str, Any]] = []
    for source in selected:
        if source.get("requires_login"):
            print(f"Skip source requiring login: {source.get('id')}", file=sys.stderr)
            continue
        if not str(source.get("base_url") or "").startswith(("http://", "https://")):
            print(f"Skip source without HTTP(S) base_url: {source.get('id')}", file=sys.stderr)
            continue
        valid.append(source)
    if not valid:
        raise ValueError("no enabled, no-login HTTP(S) sources selected.")
    return valid


def discover_candidates(sources: list[dict[str, Any]], args: argparse.Namespace) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for source in sources:
        seed_urls = source.get("seed_urls")
        if not isinstance(seed_urls, list) or not seed_urls:
            seed_urls = [source.get("base_url")]
        for seed_url in seed_urls:
            url = normalize_url(str(seed_url))
            if not url:
                continue
            if args.offline:
                add_candidate(candidates, seen_urls, source, url, title=str(source.get("name") or source.get("id")), parent_url="")
                continue
            try:
                page = fetch_page(url, timeout=args.timeout, user_agent=args.user_agent)
            except OSError as exc:
                print(f"Fetch failed: {url}: {exc}", file=sys.stderr)
                add_candidate(candidates, seen_urls, source, url, title=str(source.get("name") or source.get("id")), parent_url="", status="fetch_failed")
                continue
            add_candidate(candidates, seen_urls, source, page.url, title=page.title or str(source.get("name") or source.get("id")), parent_url="")
            for href, text in page.links[: max(args.max_links, 0)]:
                absolute = normalize_url(urljoin(page.url, href))
                if not absolute:
                    continue
                if not args.include_external and not same_host(page.url, absolute):
                    continue
                title = text or absolute.rsplit("/", 1)[-1] or absolute
                add_candidate(candidates, seen_urls, source, absolute, title=title, parent_url=page.url)
    return candidates


def fetch_page(url: str, timeout: int, user_agent: str) -> PageInfo:
    request = Request(url, headers={"User-Agent": user_agent})
    with urlopen(request, timeout=timeout) as response:
        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type and "text/plain" not in content_type:
            raise OSError(f"unsupported content type: {content_type}")
        body = response.read(1024 * 1024).decode("utf-8", errors="ignore")
    parser = LinkParser()
    parser.feed(body)
    return PageInfo(url=url, title=parser.title, links=parser.links)


def add_candidate(
    candidates: list[dict[str, Any]],
    seen_urls: set[str],
    source: dict[str, Any],
    url: str,
    title: str,
    parent_url: str,
    status: str = "needs_adaptation",
) -> None:
    if url in seen_urls:
        return
    seen_urls.add(url)
    source_id = str(source.get("id") or "source")
    candidate_id = f"{source_id}-{len(candidates) + 1:05d}"
    candidates.append(
        {
            "id": candidate_id,
            "source_id": source_id,
            "source_name": source.get("name", source_id),
            "title": normalize_space(title)[:200],
            "url": url,
            "parent_url": parent_url,
            "source_type": source.get("source_type"),
            "default_category": source.get("default_category"),
            "default_suite": source.get("default_suite"),
            "allowed_use": source.get("allowed_use"),
            "license_note": source.get("license_note"),
            "status": status,
            "needs_adaptation": True,
        }
    )


def build_output(registry_path: str, sources: list[dict[str, Any]], candidates: list[dict[str, Any]], offline: bool) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_registry": registry_path,
        "mode": "offline" if offline else "online",
        "source_count": len(sources),
        "candidate_count": len(candidates),
        "sources": [
            {
                "id": source.get("id"),
                "name": source.get("name"),
                "base_url": source.get("base_url"),
                "source_type": source.get("source_type"),
                "allowed_use": source.get("allowed_use"),
            }
            for source in sources
        ],
        "candidates": candidates,
    }


def print_summary(output: dict[str, Any], dry_run: bool) -> None:
    print(f"Fetch mode: {output.get('mode')}{' dry-run' if dry_run else ''}")
    print(f"Sources: {output.get('source_count')}")
    print(f"Candidates: {output.get('candidate_count')}")
    by_source: dict[str, int] = {}
    for candidate in output.get("candidates", []):
        source_id = str(candidate.get("source_id") or "unknown")
        by_source[source_id] = by_source.get(source_id, 0) + 1
    print(f"By source: {dict(sorted(by_source.items()))}")
    for candidate in output.get("candidates", [])[:20]:
        print(f"- {candidate.get('source_id')} {candidate.get('title')} {candidate.get('url')}")
    if len(output.get("candidates", [])) > 20:
        print(f"- ... {len(output.get('candidates', [])) - 20} more")


def normalize_url(url: str) -> str:
    stripped = url.strip()
    if not stripped.startswith(("http://", "https://")):
        return ""
    clean, _fragment = urldefrag(stripped)
    return clean


def same_host(left: str, right: str) -> bool:
    return urlparse(left).netloc.lower() == urlparse(right).netloc.lower()


def normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


if __name__ == "__main__":
    raise SystemExit(main())
