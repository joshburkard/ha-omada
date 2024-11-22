# binary_sensor.py:

"""Binary sensor platform for Omada Controller."""
from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

import logging

_LOGGER = logging.getLogger(__name__)

class OmadaDeviceBinarySensor(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor for Omada device information."""

    _attr_has_entity_name = True

    def __init__(self, coordinator, device_data, sensor_type, attribute, display_name):
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self._device_data = device_data
        self._sensor_type = sensor_type
        self._attribute = attribute
        self.entity_category = EntityCategory.DIAGNOSTIC

        # Clean up MAC address for ID
        self._device_mac = device_data.get("mac", "").replace(':', '').replace('-', '').lower()

        # Keep original case for display name
        self._device_name = device_data.get("name", device_data.get("mac", "Unknown"))
        # Lowercase version for entity_id
        device_name_lower = self._device_name.lower()

        self._device_unique_id = f"omada_device_{self._device_mac}"
        self._attr_unique_id = f"{self._device_unique_id}_{sensor_type}"

        # Set entity ID with lowercase name
        sanitized_name = device_name_lower.replace(' ', '_').replace('-', '_')
        self.entity_id = f"binary_sensor.om_device_{sanitized_name}_{sensor_type}"

        # Set display name
        self._attr_name = display_name

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._device_unique_id)},
            name=self._device_name,
            manufacturer="TP-Link",
            model="Omada Device",
            sw_version=self._device_data.get("firmwareVersion", "Unknown"),
            hw_version=self._device_data.get("hwVersion", "Unknown"),
        )

    @property
    def is_on(self) -> bool:
        """Return the state of the binary sensor."""
        value = self._device_data.get(self._attribute)
        if value is None:
            return None
        return bool(value)

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        return self._device_data is not None

def create_device_binary_sensors(coordinator, device):
    """Create binary sensors for a device based on available data."""
    sensors = []

    # Map of binary sensor definitions: (sensor_type, attribute, display_name)
    sensor_definitions = [
        ("combined_gateway", "combinedGateway", "Combined Gateway"),
        ("compatible", "compatible", "Compatible"),
        ("es", "es", "ES"),
        ("fw_download", "fwDownload", "Firmware Download"),
        ("locate_enable", "locateEnable", "Locate Enable"),
        ("need_upgrade", "needUpgrade", "Need Upgrade"),
        ("status_category", "statusCategory", "Status Category"),
    ]

    for sensor_type, attribute, display_name in sensor_definitions:
        if attribute in device:
            sensors.append(OmadaDeviceBinarySensor(
                coordinator,
                device,
                sensor_type,
                attribute,
                display_name
            ))

    return sensors

async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> bool:
    """Set up binary sensors from a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]

    @callback
    def async_update_binary_sensors():
        """Update binary sensors."""
        new_sensors = []

        # Create binary sensors for devices
        for device in coordinator.data.get("devices", {}).get("data", []):
            new_sensors.extend(create_device_binary_sensors(coordinator, device))

        if new_sensors:
            async_add_entities(new_sensors)

    coordinator.async_add_listener(async_update_binary_sensors)
    async_update_binary_sensors()

    return True