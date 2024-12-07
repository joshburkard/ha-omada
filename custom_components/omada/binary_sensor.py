"""Binary sensor platform for Test HA Omada."""
import logging
from homeassistant.components.binary_sensor import (
    BinarySensorEntity,
    BinarySensorDeviceClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import slugify
from .const import DOMAIN
from .helpers import OmadaCoordinatorEntity, standardize_mac, is_valid_value
from homeassistant.helpers.entity_registry import RegistryEntryDisabler

_LOGGER = logging.getLogger(__name__)

# Device sensor definitions tuple (entity_id, attribute, display_name)
DEVICE_SENSOR_DEFINITIONS = [
    ("combined_gateway", "combinedGateway", "Combined Gateway"),
    ("compatible", "compatible", "Compatible"),
    ("es", "es", "ES"),
    ("fw_download", "fwDownload", "Firmware Download"),
    ("locate_enable", "locateEnable", "Locate Enable"),
    ("need_upgrade", "needUpgrade", "Need Upgrade"),
    ("status_category", "statusCategory", "Status Category"),
    ("wireless_linked", "wirelessLinked", "WireLess Linked")
]

async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the binary sensors."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]["coordinator"]
    tracked_entities = {}

    @callback
    def add_entities():
        """Add new entities."""
        new_entities = []

        # Add device binary sensors
        if "devices" in coordinator.data:
            for device in coordinator.data["devices"]:
                device_mac = device.get("mac")
                if not device_mac:
                    continue

                for entity_id, attribute, display_name in DEVICE_SENSOR_DEFINITIONS:
                    entity_key = f"device_{device_mac}_{entity_id}"
                    if entity_key in tracked_entities:
                        continue

                    if not is_valid_value(device.get(attribute)):
                        continue

                    entity = OmadaDeviceBinarySensor(
                        coordinator,
                        device,
                        entity_id,
                        attribute,
                        display_name
                    )
                    tracked_entities[entity_key] = entity
                    new_entities.append(entity)

        if new_entities:
            async_add_entities(new_entities)

    coordinator.async_add_listener(add_entities)
    add_entities()

class OmadaDeviceBinarySensor(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor for Omada device attributes."""

    def __init__(self, coordinator, device, entity_id, attribute, display_name):
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self._device = device
        self._attribute = attribute
        self._display_name = display_name
        # Get device MAC and name with fallback values
        device_mac = str(device.get("mac", "unknown"))
        device_name = str(device.get("name", device_mac))
        # Set unique_id as combination of MAC and sensor type
        self._attr_unique_id = f"device_{device_mac}_{entity_id}"
        # Set name as combination of device name and sensor display name
        self._attr_name = f"{device_name} {display_name}"
        # Set up device info
        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"device_{device_mac}")},
            "name": device_name,
            "manufacturer": "TP-Link",
            "model": str(device.get("model", "Omada Device")),
            "sw_version": str(device.get("firmwareVersion", "Unknown")),
        }

    @property
    def is_on(self) -> bool:
        """Return sensor state."""
        if not isinstance(self.coordinator.data, dict) or "devices" not in self.coordinator.data:
            return False
        for device in self.coordinator.data["devices"]:
            if not isinstance(device, dict):
                continue
            if device.get("mac") == self._device.get("mac"):
                # Handle different types of boolean values
                value = device.get(self._attribute)
                if isinstance(value, bool):
                    return value
                elif isinstance(value, str):
                    return value.lower() in ['true', '1', 'yes', 'on']
                elif isinstance(value, (int, float)):
                    return bool(value)
        return False

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        if not isinstance(self.coordinator.data, dict) or "devices" not in self.coordinator.data:
            return False
        device_found = any(
            isinstance(device, dict) and device.get("mac") == self._device.get("mac")
            for device in self.coordinator.data["devices"]
        )
        return self.coordinator.last_update_success and device_found

    @property
    def extra_state_attributes(self) -> dict:
        """Return additional attributes about the sensor."""
        return {
            "attribute_name": self._attribute,
            "mac_address": str(self._device.get("mac", "unknown")),
            "entity_type": "device"
        }
