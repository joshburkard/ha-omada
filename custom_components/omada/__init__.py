"""The Test HA Omada integration."""
import asyncio
import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.helpers.entity_registry import async_get as er_async_get
from homeassistant.helpers.device_registry import async_get as dr_async_get

from .api import OmadaAPI
from .const import DOMAIN, DEFAULT_SCAN_INTERVAL

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.BINARY_SENSOR, Platform.SENSOR, Platform.DEVICE_TRACKER, Platform.SWITCH]

async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    hass.data.setdefault(DOMAIN, {})
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    api = OmadaAPI(
        base_url=entry.data["url"],
        username=entry.data["username"],
        password=entry.data["password"],
        site_name=entry.data["site_name"],
        skip_cert_verify=entry.data.get("skip_cert_verify", False)
    )

    async def async_update_data():
        try:
            await hass.async_add_executor_job(api.authenticate)

            tasks = [
                hass.async_add_executor_job(api.get_devices),
                hass.async_add_executor_job(api.get_clients),
                hass.async_add_executor_job(lambda: api.get_acl_rules(0)),
                hass.async_add_executor_job(lambda: api.get_acl_rules(1)),
                hass.async_add_executor_job(lambda: api.get_acl_rules(2)),
                hass.async_add_executor_job(api.get_networks),
                hass.async_add_executor_job(api.get_ip_groups),
                hass.async_add_executor_job(api.get_all_ssids)
            ]

            results = await asyncio.gather(*tasks)
            devices, clients, gateway_rules, switch_rules, eap_rules, networks, ip_groups, ssids = results

            if not devices or not clients:
                raise UpdateFailed("Failed to fetch data")

            new_data = {
                "devices": devices.get("result", {}).get("data", []),
                "clients": clients.get("result", {}).get("data", []),
                "acl_rules": {
                    "gateway": gateway_rules.get("result", {}).get("data", []),
                    "switch": switch_rules.get("result", {}).get("data", []),
                    "eap": eap_rules.get("result", {}).get("data", [])
                },
                "networks": networks.get("result", {}).get("data", []),
                "ip_groups": ip_groups.get("result", {}).get("data", []),
                "ssids": ssids.get("result", {}).get("data", [])
            }

            await cleanup_stale_entities(hass, entry.entry_id, new_data)
            return new_data

        except Exception as err:
            raise UpdateFailed(f"Error communicating with API: {err}")

    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name=DOMAIN,
        update_method=async_update_data,
        update_interval=DEFAULT_SCAN_INTERVAL,
    )

    await coordinator.async_config_entry_first_refresh()

    hass.data[DOMAIN][entry.entry_id] = {
        "coordinator": coordinator,
        "api": api,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True

async def cleanup_stale_entities(hass: HomeAssistant, entry_id: str, data: dict):
    """Remove stale devices and their entities."""
    device_registry = dr_async_get(hass)
    entity_registry = er_async_get(hass)

    # Get current device IDs
    current_device_macs = {device["mac"] for device in data["devices"]}
    current_acl_rules = set()
    for device_type in ["gateway", "switch", "eap"]:
        for rule in data["acl_rules"].get(device_type, []):
            current_acl_rules.add(f"acl_rule_{device_type}_{rule.get('id')}")

    # Create a list of devices to remove
    devices_to_remove = []
    for device_id, device in list(device_registry.devices.items()):
        for identifier in device.identifiers:
            if identifier[0] != DOMAIN:
                continue

            device_key = identifier[1]
            if device_key.startswith("device_"):
                mac = device_key.replace("device_", "")
                if mac not in current_device_macs:
                    devices_to_remove.append(device_id)
            elif device_key.startswith("acl_rule_"):
                if device_key not in current_acl_rules:
                    devices_to_remove.append(device_id)

    # Remove stale devices
    for device_id in devices_to_remove:
        device_registry.async_remove_device(device_id)

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
    return unload_ok