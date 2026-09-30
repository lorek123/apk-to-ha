# SPDX-License-Identifier: MIT
"""Config flow for BlueGate: discover, enrol a Home Assistant key, verify."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from bluegate_sdk import (
    SERVICE_UUIDS,
    BluegateAuthError,
    BluegateClient,
    BluegateConnectionError,
    auth,
)
from homeassistant.components import bluetooth
from homeassistant.config_entries import SOURCE_REAUTH, ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_ADDRESS

from .const import CONF_PRIVATE_KEY, DOMAIN

APP_NAME = "BlueGate"


class BluegateConfigFlow(ConfigFlow, domain=DOMAIN):
    """Each device gets its own key pair, generated here and never shown or logged.

    Only the public key is displayed, for the device's admin to enrol. The flow keeps
    the same key across retries so the admin enrols it once; reauth (the device
    rejected the key) starts over with a new key, since the old one may be revoked.
    """

    VERSION = 1

    def __init__(self) -> None:
        self._address: str | None = None
        self._title: str | None = None
        self._private_key: str | None = None
        self._discovered: dict[str, str] = {}

    async def async_step_bluetooth(
        self, discovery_info: bluetooth.BluetoothServiceInfoBleak
    ) -> ConfigFlowResult:
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()
        self._address = discovery_info.address
        self._title = discovery_info.name or discovery_info.address
        self.context["title_placeholders"] = {"name": self._title}
        return await self.async_step_enroll()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            address = user_input[CONF_ADDRESS]
            await self.async_set_unique_id(address, raise_on_progress=False)
            self._abort_if_unique_id_configured()
            self._address = address
            self._title = self._discovered.get(address, address)
            return await self.async_step_enroll()

        configured = self._async_current_ids(include_ignore=False)
        for info in bluetooth.async_discovered_service_info(self.hass, connectable=True):
            if info.address in configured:
                continue
            if any(uuid in info.service_uuids for uuid in SERVICE_UUIDS):
                self._discovered[info.address] = info.name or info.address
        if not self._discovered:
            return self.async_abort(reason="no_devices_found")
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({vol.Required(CONF_ADDRESS): vol.In(self._discovered)}),
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        self._address = entry_data[CONF_ADDRESS]
        self._title = self._get_reauth_entry().title
        self._private_key = None  # never re-enrol a key the device already rejected
        return await self.async_step_enroll()

    async def async_step_enroll(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        assert self._address is not None
        if self._private_key is None:
            self._private_key = await self.hass.async_add_executor_job(auth.generate_private_key)
        errors: dict[str, str] = {}

        if user_input is not None:
            ble_device = bluetooth.async_ble_device_from_address(
                self.hass, self._address, connectable=True
            )
            if ble_device is None:
                errors["base"] = "cannot_connect"
            else:
                client = BluegateClient(ble_device, self._private_key)
                try:
                    # Authenticates and checks permissions without actuating the device.
                    await client.verify_enrolled()
                except BluegateAuthError:
                    errors["base"] = "not_enrolled"
                except BluegateConnectionError:
                    errors["base"] = "cannot_connect"
                else:
                    data = {CONF_ADDRESS: self._address, CONF_PRIVATE_KEY: self._private_key}
                    if self.source == SOURCE_REAUTH:
                        return self.async_update_reload_and_abort(
                            self._get_reauth_entry(), data_updates=data
                        )
                    return self.async_create_entry(title=self._title or self._address, data=data)

        return self.async_show_form(
            step_id="enroll",
            description_placeholders={
                "app": APP_NAME,
                "public_key": auth.public_key_hex(self._private_key),
                "fingerprint": auth.fingerprint(self._private_key),
            },
            errors=errors,
        )
