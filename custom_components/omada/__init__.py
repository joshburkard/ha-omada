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
from .helpers import OmadaCoordinatorEntity, standardize_mac, is_valid_value

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.BINARY_SENSOR, Platform.SENSOR, Platform.DEVICE_TRACKER, Platform.SWITCH, Platform.SELECT]

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
                hass.async_add_executor_job(api.get_clients),  # This now gets both known and online clients
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

            # Get AP radio settings
            ap_radio_settings = {}
            for device in device_data:
                if device.get("type") == "ap":
                    mac = device.get("mac")
                    if mac:
                        settings = await hass.async_add_executor_job(
                            api.get_device_ssid_overrides,  # This function already gets all device settings
                            mac
                        )
                        ap_radio_settings[mac] = settings

            # Get AP device data (including radio settings)
            ap_data = {}
            for device in device_data:
                if device.get("type") == "ap":
                    mac = device.get("mac")
                    if mac:
                        _LOGGER.debug("Getting radio settings for AP %s", mac)
                        settings = await hass.async_add_executor_job(
                            api.get_device_radio,
                            mac
                        )
                        _LOGGER.debug("Radio settings response for %s: %s", mac, settings)
                        ap_data[mac] = settings
            _LOGGER.debug("Collected AP data: %s", ap_data)

            # Add to new_data dictionary:
            new_data = {
                "devices": device_data,
                "clients": clients.get("result", {}).get("data", []),  # Now includes both known and online clients
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
                "ssid_overrides": ssid_overrides,
                "ap_radio_settings": ap_radio_settings,
                "ap_data": ap_data
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
    """Clean up stale entities and devices."""
    device_registry = dr_async_get(hass)
    entity_registry = er_async_get(hass)

    # Get current device IDs
    current_device_macs = {device["mac"] for device in data["devices"]}
    current_client_macs = {standardize_mac(client["mac"]) for client in data["clients"]}
    active_client_macs = {standardize_mac(client["mac"]) for client in data["clients"] if client.get("active", False)}

    # Build ACL rules set
    current_acl_rules = set()
    for device_type in ["gateway", "switch", "eap"]:
        for rule in data["acl_rules"].get(device_type, []):
            rule_id = rule.get("id")
            if rule_id:
                device_id = f"acl_rule_{device_type}_{rule_id}"
                switch_id = f"{device_id}_status"
                current_acl_rules.add(device_id)
                current_acl_rules.add(switch_id)

    # Build URL filters set
    current_url_filters = set()
    for filter_type in ["gateway", "ap"]:
        for rule in data["url_filters"].get(filter_type, []):
            rule_id = rule.get("id")
            if rule_id:
                device_id = f"url_filter_{filter_type}_{rule_id}"
                switch_id = f"{device_id}_status"
                current_url_filters.add(device_id)
                current_url_filters.add(switch_id)

    # Build SSID overrides set
    current_ssids = set()
    for device_mac, overrides in data.get("ssid_overrides", {}).items():
        for override in overrides:
            ssid_name = override.get("ssid")
            if ssid_name:
                switch_id = f"device_{device_mac}_ssid_{ssid_name}"
                current_ssids.add(switch_id)

    # Clean up stale entities
    entities_to_remove = []

    for entry in entity_registry.entities.values():
        if entry.config_entry_id != entry_id:
            continue

        unique_id = entry.unique_id
        should_remove = False

        # Check client-related entities
        if unique_id and (unique_id.startswith("client_") or unique_id.startswith("omada_tracker_")):
            # Extract MAC address from unique_id
            parts = unique_id.split("_")
            if len(parts) >= 2:
                mac = parts[1] if unique_id.startswith("client_") else unique_id.replace("omada_tracker_", "")
                mac = standardize_mac(mac)

                # Only remove entity if client is no longer in the known clients list
                if mac not in current_client_macs:
                    should_remove = True
                    _LOGGER.debug("Marking removed client entity for removal: %s (MAC: %s)", entry.entity_id, mac)
                # For detailed sensors (except device tracker and block switch), remove if client is inactive
                elif (not unique_id.startswith("omada_tracker_") and
                      not unique_id.endswith("_blocked") and
                      mac not in active_client_macs):
                    should_remove = True
                    _LOGGER.debug("Marking inactive client sensor for removal: %s (MAC: %s)", entry.entity_id, mac)

        # Check device entities
        elif unique_id and unique_id.startswith("device_"):
            parts = unique_id.split("_")
            if len(parts) >= 2:
                mac = parts[1]
                if mac not in current_device_macs:
                    should_remove = True

        # Check ACL rule entities
        elif unique_id and unique_id.startswith("acl_rule_"):
            if unique_id not in current_acl_rules:
                should_remove = True

        # Check URL filter entities
        elif unique_id and unique_id.startswith("url_filter_"):
            if unique_id not in current_url_filters:
                should_remove = True

        # Check SSID override entities
        elif unique_id and "_ssid_" in unique_id:
            if unique_id not in current_ssids:
                should_remove = True

        if should_remove:
            entities_to_remove.append(entry.entity_id)

    # Remove stale entities
    for entity_id in entities_to_remove:
        _LOGGER.debug("Removing stale entity: %s", entity_id)
        entity_registry.async_remove(entity_id)

    # Clean up devices that have no entities
    for device_id, device in device_registry.devices.items():
        if not any(identifier[0] == DOMAIN for identifier in device.identifiers):
            continue

        has_entities = False
        for entity in entity_registry.entities.values():
            if entity.device_id == device_id and entity.entity_id not in entities_to_remove:
                has_entities = True
                break

        if not has_entities:
            _LOGGER.debug("Removing device without entities: %s", device_id)
            device_registry.async_remove_device(device_id)

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
    return unload_ok
