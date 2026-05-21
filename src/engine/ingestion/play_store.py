# SPDX-License-Identifier: MIT
"""P1 — Google Play Store metadata fetcher.

Enriches the IR with the app's public Play Store description, category,
and developer name. This context is used by:
  - strings.json / translations for the HA config flow description
  - V-4 quality rule agent (semantic understanding of what the app does)
  - Future LLM-based entity classification

Fails gracefully: returns None if the package is not on the Play Store,
the network is unavailable, or scraping fails for any reason. The pipeline
continues without Play Store data.
"""
from __future__ import annotations

import asyncio
import logging

from ..ir.models import PlayStoreInfo

_LOGGER = logging.getLogger(__name__)

_TIMEOUT = 15  # seconds — Play Store can be slow


async def fetch(package_name: str) -> PlayStoreInfo | None:
    """Fetch Play Store metadata for *package_name*. Returns None on any failure."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_fetch_sync, package_name),
            timeout=_TIMEOUT,
        )
    except TimeoutError:
        _LOGGER.info("play_store: timed out fetching %s (>%ds)", package_name, _TIMEOUT)
        return None
    except Exception as exc:
        _LOGGER.info("play_store: could not fetch %s — %s", package_name, exc)
        return None


def _fetch_sync(package_name: str) -> PlayStoreInfo | None:
    """Blocking call to google-play-scraper. Run via asyncio.to_thread."""
    from google_play_scraper import app, exceptions  # type: ignore[import-untyped]

    try:
        data = app(package_name, lang="en", country="us")
    except exceptions.NotFoundError:
        _LOGGER.info("play_store: %s not found on Play Store", package_name)
        return None

    return PlayStoreInfo(
        title=data.get("title", ""),
        description=_clean(data.get("description", "")),
        summary=_clean(data.get("summary")) if data.get("summary") else None,
        category=data.get("genre"),
        developer=data.get("developer"),
        developer_id=data.get("developerId"),
        rating=data.get("score"),
        installs=data.get("installs"),
        play_store_url=f"https://play.google.com/store/apps/details?id={package_name}",
    )


def _clean(text: str | None) -> str:
    """Strip HTML tags that sometimes appear in Play Store descriptions."""
    if not text:
        return ""
    import html
    import re
    text = html.unescape(text)
    text = re.sub(r"<[^>]+>", " ", text)   # strip tags
    text = re.sub(r"\s+", " ", text)         # collapse whitespace
    return text.strip()
