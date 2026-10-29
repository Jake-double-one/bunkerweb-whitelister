"""Tiny translation layer: one JSON file per language under ``locales/``.

Strings use ``{name}`` placeholders. English is the fallback for keys a
language leaves out, so a new language only needs the keys it changes.
"""

from __future__ import annotations

import json
from pathlib import Path

LOCALES_DIR = Path(__file__).parent / "locales"
DEFAULT_LANGUAGE = "en"


def available_languages() -> list[str]:
    return sorted(p.stem for p in LOCALES_DIR.glob("*.json"))


class Translator:
    def __init__(self, language: str) -> None:
        self.language = language if language in available_languages() else DEFAULT_LANGUAGE
        self._fallback = _load(DEFAULT_LANGUAGE)
        self._strings = _load(self.language) if self.language != DEFAULT_LANGUAGE else self._fallback

    def __call__(self, key: str, **params: object) -> str:
        template = self._strings.get(key) or self._fallback.get(key) or key
        try:
            return template.format(**params)
        except (KeyError, IndexError, ValueError):
            return template

    def plural(self, key: str, count: int, **params: object) -> str:
        """``key.one`` for 1, ``key.other`` otherwise."""
        suffix = ".one" if count == 1 else ".other"
        return self(key + suffix, count=count, **params)


def _load(language: str) -> dict[str, str]:
    path = LOCALES_DIR / f"{language}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if isinstance(v, str)}
