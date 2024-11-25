"""
Device Tracker platform for Omada Controller.
"""

from homeassistant.components.device_tracker.config_entry import TrackerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from .const import DOMAIN
import logging

_LOGGER = logging.getLogger(__name__)

class OmadaDeviceTracker(CoordinatorEntity, TrackerEntity):
    """Base class for Omada device tracker."""

    def __init__(self, coordinator, device_data, device_type):
        """Initialize the device tracker."""
        super().__init__(coordinator)
        self._device_data = device_data
        self._device_type = device_type
        self._device_mac = device_data.get("mac", "").replace(':', '').replace('-', '').lower()

        # Keep original case for display name
        self._device_name = device_data.get("name", device_data.get("mac", "Unknown"))
        # Lowercase version for entity_id
        device_name_lower = self._device_name.lower()

        # Map device type to string
        type_map = {0: "gateway", 1: "switch", 2: "eap"}
        device_type_str = type_map.get(device_type, "unknown")

        self._device_unique_id = f"omada_device_{device_type_str}_{self._device_mac}"
        self._attr_unique_id = self._device_unique_id

        # Set new entity_id format using lowercase name
        sanitized_name = device_name_lower.replace(' ', '_').replace('-', '_')
        self.entity_id = f"device_tracker.om_device_{device_type_str}_{sanitized_name}"
        self._attr_name = self._device_name  # Original case

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        # Map device type to string for model name
        type_map = {0: "Gateway", 1: "Switch", 2: "EAP"}
        device_type_str = type_map.get(self._device_type, "Unknown")

        return DeviceInfo(
            identifiers={(DOMAIN, self._device_unique_id)},
            name=self._device_name,
            manufacturer="TP-Link",
            model=f"Omada {device_type_str}",
            via_device=(DOMAIN, "omada_controller"),
        )

    @property
    def state(self):
        """Return the state of the device."""
        connected = self._device_data is not None
        _LOGGER.debug("Device %s is_connected: %s", self._device_name, connected)
        return "home" if connected else "not_home"

    @property
    def source_type(self):
        """Return the source type of the device."""
        return "router"

    @property
    def should_poll(self):
        """No polling needed for this entity."""
        return False

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        _LOGGER.debug("Updating device tracker for %s", self._device_name)
        if updated_data := self._get_updated_data():
            self._device_data = updated_data
        else:
            self._device_data = None
        self.async_write_ha_state()

    def _get_updated_data(self):
        """Get the latest device data."""
        if not self.coordinator.data.get("devices", {}).get("data"):
            return None
        for device in self.coordinator.data["devices"]["data"]:
            if device.get("mac", "").replace(':', '').replace('-', '').lower() == self._device_mac:
                return device
        return None

class OmadaClientTracker(CoordinatorEntity, TrackerEntity):
    """Base class for Omada client tracker."""

    def __init__(self, coordinator, client_data):
        """Initialize the client tracker."""
        super().__init__(coordinator)
        self._client_data = client_data
        self._client_mac = client_data.get("mac", "").replace(':', '').replace('-', '').lower()
        self._client_name = client_data.get("name", client_data.get("mac", "Unknown"))

        # Match the same device_unique_id format as sensors
        self._device_unique_id = f"omada_client_{self._client_mac}"
        self._attr_unique_id = f"{self._device_unique_id}_tracker"

        # Determine if client is wireless
        is_wireless = client_data.get("wireless", False)
        client_type = "wireless" if is_wireless else "wired"

        # Set entity_id format
        sanitized_name = self._client_name.lower().replace(' ', '_').replace('-', '_')
        self.entity_id = f"device_tracker.om_client_{client_type}_{sanitized_name}"
        self._attr_name = self._client_name

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._device_unique_id)},
            name=self._client_name,
            manufacturer="TP-Link",
            model="Omada Client",
            via_device=(DOMAIN, "omada_controller"),
        )

    @property
    def state(self):
        """Return the state of the client."""
        connected = self._client_data is not None
        _LOGGER.debug("Client %s is_connected: %s", self._client_name, connected)
        return "home" if connected else "not_home"

    @property
    def source_type(self):
        """Return the source type of the client."""
        return "router"

    @property
    def should_poll(self):
        """No polling needed for this entity."""
        return False

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        _LOGGER.debug("Updating client tracker for %s", self._client_name)
        if updated_data := self._get_updated_data():
            self._client_data = updated_data
        else:
            self._client_data = None
        self.async_write_ha_state()

    def _get_updated_data(self):
        """Get the latest client data."""
        if not self.coordinator.data.get("clients", {}).get("data"):
            return None
        for client in self.coordinator.data["clients"]["data"]:
            if client.get("mac", "").replace(':', '').replace('-', '').lower() == self._client_mac:
                return client
        return None

def create_device_trackers(coordinator, device):
    """Create device trackers for a device based on available data."""
    device_type = device.get("deviceType", -1)
    if device_type in [0, 1, 2]:  # Only create trackers for known device types
        return [OmadaDeviceTracker(coordinator, device, device_type)]
    return []

def create_client_trackers(coordinator, client):
    """Create device trackers for a client based on available data."""
    return [OmadaClientTracker(coordinator, client)]

async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> bool:
    """Set up device trackers from a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities = []

    @callback
    def update_entities():
        """Update entities with new clients and devices."""
        _LOGGER.debug("Updating entities with new clients and devices")
        new_entities = []

        # Create device trackers for clients
        for client in coordinator.data.get("clients", {}).get("data", []):
            new_entities.extend(create_client_trackers(coordinator, client))

        # Create device trackers for devices
        for device in coordinator.data.get("devices", {}).get("data", []):
            new_entities.extend(create_device_trackers(coordinator, device))

        async_add_entities(new_entities)

    coordinator.async_add_listener(update_entities)
    update_entities()
    return True
