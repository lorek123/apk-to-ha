# SPDX-License-Identifier: MIT
"""Static-extraction confidence: how sure we are an endpoint is right, by evidence.

An endpoint's confidence is (evidence for its name) x (evidence for its request
fields). Static analysis alone rarely proves both, so most static scores sit
below the oracle threshold (0.9) on purpose: the dynamic oracle (P2-7) is what
confirms them, and the reconciler raises confidence for what it observed.
"""

from __future__ import annotations

from ..ir.models import Endpoint

# Evidence for the command name
NAME_ANNOTATION = 0.95  # Retrofit @GET("/path") etc.: declarative, compiler-checked
NAME_CMD_PUT = 0.9  # put("cmd", "x") or put("cmd", CONST) with the constant resolved
NAME_LISTED = 0.8  # only named in a command-list constant; no send/receive site found
NAME_REQUEST_CALL = 0.85  # HTTP request built at a call site; path assembled from pieces

# Evidence for the request fields
FIELDS_TYPED = 1.0  # declared by the method signature / a typed body class
FIELDS_NONE = 0.9  # none found — absence is not proof there are none
FIELDS_NEARBY = 0.85  # other put() calls near the cmd: a proximity heuristic

# Confirmed by the dynamic oracle: seen on the wire during a live capture.
OBSERVED = 0.95

# Endpoints below this are called out in the IR's extractor notes.
LOW_CONFIDENCE = 0.7


def score(name: float, fields: float) -> float:
    return round(name * fields, 2)


def summarize(endpoints: list[Endpoint]) -> tuple[float, list[str]]:
    """Overall extraction confidence (mean over endpoints) and notes on weak ones."""
    if not endpoints:
        return 0.0, ["no endpoints extracted"]
    overall = round(sum(e.confidence for e in endpoints) / len(endpoints), 2)
    weak = sorted(e.cmd for e in endpoints if e.confidence < LOW_CONFIDENCE)
    notes = [f"low confidence (<{LOW_CONFIDENCE}): {', '.join(weak)}"] if weak else []
    return overall, notes
