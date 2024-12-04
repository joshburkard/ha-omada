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
from .helpers import standardize_mac

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.BINARY_SENSOR, Platform.SENSOR, Platform.DEVICE_TRACKER, Platform.SWITCH, Platform.SELECT]

async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the Omada component."""
    hass.data.setdefault(DOMAIN, {})
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Omada from a config entry."""
    api = OmadaAPI(
        base_url=entry.data["url"],
        username=entry.data["username"],
        password=entry.data["password"],
        site_name=entry.data["site_name"],
        skip_cert_verify=entry.data.get("skip_cert_verify", False)
    )

    try:
        authenticated = await hass.async_add_executor_job(api.authenticate)
        if not authenticated:
            _LOGGER.error("Failed to authenticate with Omada Controller")
            return False
    except Exception as err:
        _LOGGER.error("Error authenticating with Omada Controller: %s", err)
        return False

    class OmadaDataUpdateCoordinator(DataUpdateCoordinator):
        """Class to manage fetching Omada data."""

        def __init__(self, hass, api):
            """Initialize the coordinator."""
            super().__init__(
                hass,
                _LOGGER,
                name=DOMAIN,
                update_interval=DEFAULT_SCAN_INTERVAL,
            )
            self.api = api
            self._last_known_data = None
            self._error_count = 0

        async def _async_update_data(self):
            """Fetch data from API."""
            try:
                if not self.api.token:
                    await self.hass.async_add_executor_job(self.api.authenticate)

                # Get devices
                device_data = await self.hass.async_add_executor_job(self.api.get_devices)
                device_data = device_data.get("result", {}).get("data", [])

                # Get and process clients
                clients_dict = {}
                known_clients_response = await self.hass.async_add_executor_job(self.api.get_known_clients)
                online_clients_response = await self.hass.async_add_executor_job(self.api.get_online_clients)

                # Process known clients
                for client in known_clients_response.get("result", {}).get("data", []):
                    mac = standardize_mac(client.get("mac", ""))
                    if mac:
                        clients_dict[mac] = dict(client)
                        clients_dict[mac]["active"] = False

                # Process online clients
                for client in online_clients_response.get("result", {}).get("data", []):
                    mac = standardize_mac(client.get("mac", ""))
                    if not mac:
                        continue

                    if mac in clients_dict:
                        clients_dict[mac].update(dict(client))
                    else:
                        clients_dict[mac] = dict(client)
                    clients_dict[mac]["active"] = True

                all_clients = list(clients_dict.values())

                # Get rules and settings
                results = await asyncio.gather(
                    self.hass.async_add_executor_job(lambda: self.api.get_acl_rules(0)),
                    self.hass.async_add_executor_job(lambda: self.api.get_acl_rules(1)),
                    self.hass.async_add_executor_job(lambda: self.api.get_acl_rules(2)),
                    self.hass.async_add_executor_job(self.api.get_networks),
                    self.hass.async_add_executor_job(self.api.get_ip_groups),
                    self.hass.async_add_executor_job(self.api.get_all_ssids),
                    self.hass.async_add_executor_job(lambda: self.api.get_url_filters("gateway")),
                    self.hass.async_add_executor_job(lambda: self.api.get_url_filters("ap"))
                )

                gateway_rules, switch_rules, eap_rules, networks, ip_groups, ssids, gateway_url_filters, eap_url_filters = results

                # Process AP devices data
                ssid_overrides = {}
                ap_data = {}

                # Create a list of AP devices
                ap_devices = [device for device in device_data if device.get("type") == "ap"]

                # Then process each AP device
                for device in ap_devices:
                    mac = device.get("mac")
                    if mac:
                        try:
                            # Get radio settings
                            radio_result = await self.hass.async_add_executor_job(
                                self.api.get_device_radio,
                                mac
                            )
                            if radio_result:
                                ap_data[mac] = radio_result

                            # Get SSID overrides
                            override_result = await self.hass.async_add_executor_job(
                                self.api.get_device_ssid_overrides,
                                mac
                            )
                            if override_result:
                                ssid_overrides[mac] = override_result

                        except Exception as e:
                            _LOGGER.error("Error getting AP device data for %s: %s", mac, str(e))
                            # Use last known data if available
                            if self._last_known_data:
                                ap_data[mac] = self._last_known_data["ap_data"].get(mac, {})
                                ssid_overrides[mac] = self._last_known_data["ssid_overrides"].get(mac, {})

                new_data = {
                    "devices": device_data,
                    "clients": all_clients,
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
                    "ap_data": ap_data
                }

                # Reset error count on successful update
                self._error_count = 0
                self._last_known_data = new_data
                return new_data

            except Exception as err:
                self._error_count += 1
                _LOGGER.error("Error fetching omada data: %s", str(err))

                # Only raise UpdateFailed after multiple consecutive errors
                if self._error_count >= 3:
                    raise UpdateFailed(f"Error communicating with API: {err}")

                # Return last known data if available
                if self._last_known_data:
                    return self._last_known_data

                raise UpdateFailed(f"Error communicating with API: {err}")

    coordinator = OmadaDataUpdateCoordinator(hass, api)
    await coordinator.async_config_entry_first_refresh()

    hass.data[DOMAIN][entry.entry_id] = {
        "coordinator": coordinator,
        "api": api,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        api = hass.data[DOMAIN][entry.entry_id]["api"]
        await hass.async_add_executor_job(api.disconnect)
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok

async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry."""
    _LOGGER.info("Reloading Omada integration")

    # Ensure clean disconnect of existing API
    if entry.entry_id in hass.data.get(DOMAIN, {}):
        try:
            api = hass.data[DOMAIN][entry.entry_id]["api"]
            await hass.async_add_executor_job(api.disconnect)
        except Exception as err:
            _LOGGER.error("Error disconnecting API during reload: %s", str(err))

    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)

async def cleanup_stale_entities(hass: HomeAssistant, entry_id: str, data: dict):
    """Clean up stale entities."""
    device_registry = dr_async_get(hass)
    entity_registry = er_async_get(hass)

    # Get current device IDs
    current_device_macs = {standardize_mac(device["mac"]) for device in data["devices"]}
    current_client_macs = {standardize_mac(client["mac"]) for client in data["clients"]}

    entities_to_remove = []

    for entry in entity_registry.entities.values():
        if entry.config_entry_id != entry_id:
            continue

        unique_id = entry.unique_id
        if not unique_id:
            continue

        should_remove = False

        # Only remove entities for clients that are completely gone
        if unique_id.startswith("client_"):
            parts = unique_id.split("_")
            if len(parts) >= 2:
                mac = standardize_mac(parts[1])
                if mac not in current_client_macs:
                    should_remove = True
                    _LOGGER.debug("Marking client entity for removal: %s (MAC: %s)", entry.entity_id, mac)

        # Handle device trackers
        elif unique_id.startswith(f"{entry_id}_tracker_"):
            mac = standardize_mac(unique_id.replace(f"{entry_id}_tracker_", ""))
            if mac not in current_client_macs:
                should_remove = True
                _LOGGER.debug("Marking device tracker for removal: %s (MAC: %s)", entry.entity_id, mac)

        # Handle device entities
        elif unique_id.startswith("device_"):
            parts = unique_id.split("_")
            if len(parts) >= 2:
                mac = standardize_mac(parts[1])
                if mac not in current_device_macs:
                    should_remove = True

        if should_remove:
            entities_to_remove.append(entry.entity_id)

    # Remove stale entities
    for entity_id in entities_to_remove:
        _LOGGER.info("Removing stale entity: %s", entity_id)
        entity_registry.async_remove(entity_id)

    # Clean up devices that have no entities
    devices_to_remove = []

    for device_id, device in device_registry.devices.items():
        if not any(identifier[0] == DOMAIN for identifier in device.identifiers):
            continue

        has_entities = False
        for entity in entity_registry.entities.values():
            if entity.device_id == device_id and entity.entity_id not in entities_to_remove:
                has_entities = True
                break

        if not has_entities:
            devices_to_remove.append(device_id)

    # Remove stale devices
    for device_id in devices_to_remove:
        _LOGGER.info("Removing device without entities: %s", device_id)
        device_registry.async_remove_device(device_id)
