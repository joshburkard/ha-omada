"""Device tracker for Test HA Omada."""
from typing import Any
import re

from homeassistant.components.device_tracker import SourceType, TrackerEntity
from homeassistant.components.device_tracker.const import ATTR_SOURCE_TYPE, DOMAIN as TRACKER_DOMAIN
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.entity_registry import async_get as er_async_get

from .helpers import OmadaCoordinatorEntity, standardize_mac
from .const import DOMAIN

import logging
_LOGGER = logging.getLogger(__name__)
_TRACKERS = {}  # Store trackers globally

async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up device tracker for Omada Clients."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]["coordinator"]
    entity_registry = er_async_get(hass)

    @callback
    def async_add_clients():
        """Add new clients."""
        new_clients = []

        for client in coordinator.data["clients"]:
            mac = client.get("mac")
            if not mac:
                continue

            # Standardize MAC address format
            mac = standardize_mac(mac)
            tracker_id = f"{config_entry.entry_id}_tracker_{mac}"

            # Check if entity exists in registry
            tracker_exists = False
            for entity in entity_registry.entities.values():
                if entity.unique_id == tracker_id:
                    tracker_exists = True
                    break

            if not tracker_exists and tracker_id not in _TRACKERS:
                tracker = OmadaClientTracker(coordinator, client, config_entry.entry_id)
                _TRACKERS[tracker_id] = tracker
                new_clients.append(tracker)
                _LOGGER.debug("Creating new device tracker %s for client %s", tracker_id, mac)

        if new_clients:
            async_add_entities(new_clients)

    coordinator.async_add_listener(async_add_clients)
    async_add_clients()

class OmadaClientTracker(OmadaCoordinatorEntity, TrackerEntity):
    """Representation of a network device."""

    def __init__(self, coordinator, client, entry_id):
        """Initialize the device."""
        super().__init__(coordinator)
        self._client = client
        self._mac = standardize_mac(client['mac'])
        self._attr_unique_id = f"{entry_id}_tracker_{self._mac}"
        self._attr_name = client.get('name', self._mac)
        self._attr_entity_category = None

        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"client_{self._mac}")},
            "name": self.name,
            "manufacturer": client.get("manufacturer", "TP-Link"),
            "model": "Omada Client",
            "sw_version": client.get("os", "Unknown"),
            "connections": {("mac", self._mac)}
        }

        self._last_ip = client.get("ip")
        self._last_mac = self._mac

    @property
    def source_type(self) -> SourceType:
        """Return the source type."""
        return SourceType.ROUTER

    @property
    def state(self) -> str:
        """Return the state of the device."""
        return "home" if self.is_connected else "not_home"

    @property
    def is_connected(self) -> bool:
        """Return true if the client is connected."""
        for client in self.coordinator.data["clients"]:
            if standardize_mac(client["mac"]) == self._mac:
                # Check if client is in the online clients list (has active property)
                if "active" in client:
                    return client["active"]
                # For backward compatibility, if active property doesn't exist
                return bool(client.get("status", False))
        return False

    @property
    def ip_address(self) -> str | None:
        """Return the primary ip address."""
        # Update IP address if client is found in current data
        for client in self.coordinator.data["clients"]:
            if standardize_mac(client["mac"]) == self._mac:
                self._last_ip = client.get("ip", self._last_ip)
                break
        return self._last_ip

    @property
    def mac_address(self) -> str | None:
        """Return the mac address."""
        return self._last_mac

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the device state attributes."""
        return {
            ATTR_SOURCE_TYPE: self.source_type,
            "ip": self._last_ip,
            "mac": self._last_mac
        }

    def _is_client_in_data(self) -> bool:
        """Check if the client is in current data."""
        return any(
            standardize_mac(client["mac"]) == self._mac
            for client in self.coordinator.data["clients"]
        )
