# SPDX-License-Identifier: MIT
# F-5 — Sandbox Docker base image for V-3 container tests.
#
# Layers dev tooling (ruff, mypy, pytest) on top of the pinned HA Core image
# so V-3 tests run against the real HA runtime without network calls at test time.
#
# Build:  make sandbox
# Run:    docker run --rm hacs-engine-sandbox pytest /sandbox/tests/ -v
# V-3:    container_test.py uses this image only when its phcc label matches the pin.

ARG HA_TAG=2026.5.2
FROM homeassistant/home-assistant:${HA_TAG}

# pytest-homeassistant-custom-component pinned to the exact HA version of this image
# (config/ha_target.toml [sandbox].phcc_version). It brings pytest, pytest-asyncio and
# HA's test fixtures; V-3 runs the generated runtime tests with it.
ARG PHCC_VERSION
RUN test -n "${PHCC_VERSION}" \
    && pip install --no-cache-dir \
        "pytest-homeassistant-custom-component==${PHCC_VERSION}" \
        ruff \
        mypy
LABEL org.hacs-engine.phcc-version="${PHCC_VERSION}"

# Copy the sandbox health tests into the image
COPY tests/ /sandbox/tests/
WORKDIR /sandbox

# Default: run the health tests; callers override CMD to run integration tests
CMD ["pytest", "/sandbox/tests/", "-v"]
