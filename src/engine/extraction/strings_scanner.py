# SPDX-License-Identifier: MIT
"""P5-6 — Android strings.xml → HA translation strings.

Parses resources/res/values/strings.xml from the JADX decompilation output,
filters to user-facing error/status strings, and returns them as a plain dict.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from defusedxml import ElementTree

_LOGGER = logging.getLogger(__name__)

# String names matching any of these are candidates
_INCLUDE_RE = re.compile(
    r"error|err_|fail|success|connect|disconnect|status|state|offline|online|"
    r"paired|unpair|warn|alert|timeout|retry|lost|found|ready|busy|unavail",
    re.I,
)

# String names matching these prefixes are excluded (UI scaffolding, not device state)
_EXCLUDE_RE = re.compile(
    r"^(?:activity_|fragment_|menu_|pref_|tab_|hint_|btn_|ic_|app_name$|"
    r"title_(?!.*(?:error|status|connect|fail|warn)))",
    re.I,
)

# Skip values with Android printf specifiers or HTML tags
_HAS_FORMAT_RE = re.compile(r"%[0-9]*[$]?[dsfb]|<[a-z]+\s*/?>", re.I)

_MIN_LEN = 4
_MAX_LEN = 200


def scan(apk_out_dir: Path) -> dict[str, str]:
    """Return {name: value} for filtered user-facing strings from strings.xml.

    Returns an empty dict if the file is missing or unparseable.
    """
    xml_path = apk_out_dir / "resources" / "res" / "values" / "strings.xml"
    if not xml_path.exists():
        _LOGGER.debug("strings.xml not found at %s", xml_path)
        return {}

    try:
        tree = ElementTree.parse(xml_path)
    except ElementTree.ParseError as exc:
        _LOGGER.warning("Failed to parse strings.xml: %s", exc)
        return {}

    root = tree.getroot()
    if root is None:
        return {}
    result: dict[str, str] = {}

    for elem in root.findall("string"):
        name = elem.get("name", "")
        # Skip strings with inline markup (<b>, <i>, etc.) — ambiguous after stripping
        if len(list(elem)) > 0:
            continue
        value = (elem.text or "").strip()

        if not name or not value:
            continue
        if len(value) < _MIN_LEN or len(value) > _MAX_LEN:
            continue
        if _HAS_FORMAT_RE.search(value):
            continue
        if _EXCLUDE_RE.match(name):
            continue
        if not _INCLUDE_RE.search(name):
            continue

        result[name] = value

    _LOGGER.debug(
        "strings.xml: extracted %d relevant strings from %s elements",
        len(result),
        len(list(root)),
    )
    return result
