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
        self._device_name = device_data.get("name", device_data.get("mac", "Unknown"))
        self._device_unique_id = f"omada_device_{self._device_mac}"
        self._attr_unique_id = self._device_unique_id
        self._attr_name = self._device_name

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._device_unique_id)},
            name=self._device_name,
            manufacturer="TP-Link",
            model="Omada Device",
            via_device=(DOMAIN, "omada_controller"),
        )

    @property
    def state(self):
        """Return the state of the device."""
        connected = self._device_data is not None
        _LOGGER.info("Device %s is_connected: %s", self._device_name, connected)
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
        _LOGGER.info("Updating device tracker for %s", self._device_name)
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
        self._device_unique_id = f"omada_client_{self._client_mac}"
        self._attr_unique_id = self._device_unique_id
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
        _LOGGER.info("Client %s is_connected: %s", self._client_name, connected)
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
        _LOGGER.info("Updating client tracker for %s", self._client_name)
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
    return [OmadaDeviceTracker(coordinator, device, "device")]

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
        _LOGGER.info("Updating entities with new clients and devices")
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
