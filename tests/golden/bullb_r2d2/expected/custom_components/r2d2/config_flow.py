# SPDX-License-Identifier: MIT
"""Config flow for Build Your Own R2-D2."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client, instance_id
from r2d2_sdk import (
    R2D2AuthError,
    R2D2Client,
    R2D2ConnectionError,
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
    """Pair with grantAccess and wait for a state push to verify the device."""
    client = R2D2Client(
        host=data[CONF_HOST],
        port=data.get(CONF_PORT, DEFAULT_PORT),
        session=aiohttp_client.async_get_clientsession(hass),
    )
    try:
        # Same identity the coordinator uses, so the device sees one paired client.
        await client.connect(device_uuid=await instance_id.async_get(hass))
    except R2D2AuthError as exc:
        raise InvalidAuth from exc
    except R2D2ConnectionError as exc:
        raise CannotConnect from exc
    finally:
        await client.disconnect()

    return {"title": f"Build Your Own R2-D2 @ {data[CONF_HOST]}"}


class CannotConnect(Exception):
    """Error to indicate we cannot connect."""


class InvalidAuth(Exception):
    """Error to indicate the device rejected pairing."""


class R2D2ConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Build Your Own R2-D2.

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
