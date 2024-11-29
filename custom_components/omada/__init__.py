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

            # Get basic data first
            tasks = [
                hass.async_add_executor_job(api.get_devices),
                hass.async_add_executor_job(api.get_clients),
                hass.async_add_executor_job(lambda: api.get_acl_rules(0)),
                hass.async_add_executor_job(lambda: api.get_acl_rules(1)),
                hass.async_add_executor_job(lambda: api.get_acl_rules(2)),
                hass.async_add_executor_job(api.get_networks),
                hass.async_add_executor_job(api.get_ip_groups),
                hass.async_add_executor_job(api.get_all_ssids),
                hass.async_add_executor_job(lambda: api.get_url_filters("gateway")),
                hass.async_add_executor_job(lambda: api.get_url_filters("ap"))
            ]

            results = await asyncio.gather(*tasks)
            devices, clients, gateway_rules, switch_rules, eap_rules, networks, ip_groups, ssids, gateway_url_filters, eap_url_filters = results

            # Get SSID overrides for EAP devices
            ssid_override_tasks = []
            device_macs = []
            device_data = devices.get("result", {}).get("data", [])

            _LOGGER.debug("Processing devices for SSID overrides")
            for device in device_data:
                if device.get("type") == "ap":
                    mac = device.get("mac")
                    _LOGGER.debug("Found EAP device: %s", mac)
                    device_macs.append(mac)
                    ssid_override_tasks.append(
                        hass.async_add_executor_job(
                            api.get_device_ssid_overrides,
                            mac
                        )
                    )

            if ssid_override_tasks:
                _LOGGER.debug("Fetching SSID overrides for %d devices", len(ssid_override_tasks))
                ssid_override_results = await asyncio.gather(*ssid_override_tasks)
                ssid_overrides = dict(zip(device_macs, ssid_override_results))
                _LOGGER.debug("SSID overrides data: %s", ssid_overrides)
            else:
                _LOGGER.debug("No EAP devices found for SSID overrides")
                ssid_overrides = {}

            # Add to new_data dictionary:
            new_data = {
                "devices": device_data,
                "clients": clients.get("result", {}).get("data", []),
                "acl_rules": {
                    "gateway": gateway_rules.get("result", {}).get("data", []),
                    "switch": switch_rules.get("result", {}).get("data", []),
                    "eap": eap_rules.get("result", {}).get("data", [])
                },
                "networks": networks.get("result", {}).get("data", []),
                "ip_groups": ip_groups.get("result", {}).get("data", []),
                "ssids": ssids.get("result", {}).get("data", []),
                "url_filters": {
                    "gateway": gateway_url_filters.get("result", {}).get("data", []),
                    "ap": eap_url_filters.get("result", {}).get("data", [])
                },
                "ssid_overrides": ssid_overrides
            }

            _LOGGER.debug("Final coordinator data structure: %s", new_data.keys())
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

    current_url_filters = set()
    for filter_type in ["gateway", "ap"]:
        for rule in data["url_filters"].get(filter_type, []):
            current_url_filters.add(f"url_filter_{filter_type}_{rule.get('id')}")

    current_ssids = set()
    for device_mac, overrides in data.get("ssid_overrides", {}).items():
        for override in overrides:
            ssid_name = override.get("ssid")
            if ssid_name:
                current_ssids.add(f"device_{device_mac}_ssid_{ssid_name}")

    # Clean up stale entities
    entities_to_remove = []
    for entry in entity_registry.entities.values():
        if entry.domain == "switch":
            # Check SSID switches
            if entry.unique_id.startswith("device_") and "_ssid_" in entry.unique_id:
                if entry.unique_id not in current_ssids:
                    entities_to_remove.append(entry.entity_id)
            # Check ACL rule switches
            elif entry.unique_id.startswith("acl_rule_"):
                if entry.unique_id not in current_acl_rules:
                    entities_to_remove.append(entry.entity_id)
            # Check URL filter switches
            elif entry.unique_id.startswith("url_filter_"):
                if entry.unique_id not in current_url_filters:
                    entities_to_remove.append(entry.entity_id)

    # Remove stale entities
    for entity_id in entities_to_remove:
        entity_registry.async_remove(entity_id)

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
            elif device_key.startswith("url_filter_"):
                if device_key not in current_url_filters:
                    devices_to_remove.append(device_id)

    # Remove stale devices
    for device_id in devices_to_remove:
        device_registry.async_remove_device(device_id)

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
    return unload_ok