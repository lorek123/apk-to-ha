# SPDX-License-Identifier: MIT
"""BlueGate Home Assistant integration."""
from __future__ import annotations

from bluegate_sdk import BluegateClient
from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryNotReady

from .const import CONF_PRIVATE_KEY

PLATFORMS: list[Platform] = [Platform.BUTTON]

type BluegateConfigEntry = ConfigEntry[BluegateClient]


async def async_setup_entry(hass: HomeAssistant, entry: BluegateConfigEntry) -> bool:
    address: str = entry.data[CONF_ADDRESS]
    ble_device = bluetooth.async_ble_device_from_address(hass, address, connectable=True)
    if ble_device is None:
        raise ConfigEntryNotReady(f"{address} is not in range of any Bluetooth adapter")
    entry.runtime_data = BluegateClient(ble_device, entry.data[CONF_PRIVATE_KEY])

    @callback
    def _update_ble_device(
        service_info: bluetooth.BluetoothServiceInfoBleak, change: bluetooth.BluetoothChange
    ) -> None:
        entry.runtime_data.set_ble_device(service_info.device)

    entry.async_on_unload(
        bluetooth.async_register_callback(
            hass,
            _update_ble_device,
            bluetooth.BluetoothCallbackMatcher(address=address, connectable=True),
            bluetooth.BluetoothScanningMode.PASSIVE,
        )
    )
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: BluegateConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
