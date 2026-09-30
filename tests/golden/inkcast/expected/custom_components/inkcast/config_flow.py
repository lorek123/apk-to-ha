# SPDX-License-Identifier: MIT
"""Config flow for Inkcast."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client
from inkcast_sdk import (
    InkcastAuthError,
    InkcastClient,
    InkcastConnectionError,
)

from .const import DEFAULT_PORT, DOMAIN

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
    }
)


async def _validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Fetch the device's state once to verify it answers."""
    client = InkcastClient(
        host=data[CONF_HOST],
        port=data.get(CONF_PORT, DEFAULT_PORT),
        session=aiohttp_client.async_get_clientsession(hass),
    )
    try:
        await client.get_state()
    except InkcastAuthError as exc:
        raise InvalidAuth from exc
    except InkcastConnectionError as exc:
        raise CannotConnect from exc
    finally:
        await client.disconnect()

    return {"title": f"Inkcast @ {data[CONF_HOST]}"}


class CannotConnect(Exception):
    """Error to indicate we cannot connect."""


class InvalidAuth(Exception):
    """Error to indicate the device rejected pairing."""


class InkcastConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Inkcast.

    Every path uses the device host as unique_id so manual and discovered
    entries for the same device are recognised as one.
    """

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            await self.async_set_unique_id(user_input[CONF_HOST])
            self._abort_if_unique_id_configured()
            try:
                info = await _validate_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(title=info["title"], data=user_input)

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )
