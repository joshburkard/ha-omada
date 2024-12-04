"""Device tracker for Test HA Omada."""
from typing import Any

from homeassistant.components.device_tracker import SourceType, TrackerEntity
from homeassistant.components.device_tracker.const import ATTR_SOURCE_TYPE, DOMAIN as TRACKER_DOMAIN
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.entity_registry import async_get as er_async_get

from .helpers import OmadaCoordinatorEntity
from .const import DOMAIN

from typing import Any

async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up device tracker for Omada Clients."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]["coordinator"]
    tracked_clients = {}
    entity_registry = er_async_get(hass)

    @callback
    def async_add_clients():
        """Add new clients."""
        new_clients = []

        for client in coordinator.data["clients"]:
            mac = client.get("mac")
            if not mac:
                continue

            if mac not in tracked_clients:
                tracker = OmadaClientTracker(coordinator, client)
                tracked_clients[mac] = tracker
                new_clients.append(tracker)
            else:
                # Client exists but might be coming back online - ensure entities exist
                if client.get("active", False):
                    # Check if entity was previously removed
                    entity_id = f"device_tracker.{tracked_clients[mac].name}".lower().replace(" ", "_")
                    if not entity_registry.async_get(entity_id):
                        # Re-add the tracker if it doesn't exist
                        tracker = OmadaClientTracker(coordinator, client)
                        tracked_clients[mac] = tracker
                        new_clients.append(tracker)

        if new_clients:
            async_add_entities(new_clients)

    coordinator.async_add_listener(async_add_clients)
    async_add_clients()

class OmadaClientTracker(OmadaCoordinatorEntity, TrackerEntity):
    """Representation of a network device."""

    def __init__(self, coordinator, client):
        """Initialize the device."""
        super().__init__(coordinator)
        self._client = client
        self._attr_unique_id = f"omada_tracker_{client['mac']}"
        self._attr_name = client.get('name', client['mac'])
        self._attr_entity_category = None

        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"client_{client['mac']}")},
            "name": self.name,
            "manufacturer": client.get("manufacturer", "TP-Link"),
            "model": "Omada Client",
            "sw_version": client.get("os", "Unknown"),
        }

        self._last_ip = client.get("ip")
        self._last_mac = client.get("mac")

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
            if client["mac"] == self._client["mac"]:
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
            if client["mac"] == self._client["mac"]:
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
            client["mac"] == self._client["mac"]
            for client in self.coordinator.data["clients"]
        )
