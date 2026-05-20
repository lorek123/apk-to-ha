# SPDX-License-Identifier: MIT
# F-5 — Sandbox Docker base image for V-3 container tests.
#
# Layers dev tooling (ruff, mypy, pytest) on top of the pinned HA Core image
# so V-3 tests run against the real HA runtime without network calls at test time.
#
# Build:  make sandbox
# Run:    docker run --rm hacs-engine-sandbox pytest /sandbox/tests/ -v

ARG HA_TAG=2026.5.2
FROM homeassistant/home-assistant:${HA_TAG}

# Install dev tooling into the same Python that HA uses
RUN pip install --no-cache-dir \
    ruff==0.11.13 \
    mypy==1.16.0 \
    pytest==8.4.0 \
    pytest-asyncio==1.0.0

# Copy the sandbox health tests into the image
COPY tests/ /sandbox/tests/
WORKDIR /sandbox

# Default: run the health tests; callers override CMD to run integration tests
CMD ["pytest", "/sandbox/tests/", "-v"]
