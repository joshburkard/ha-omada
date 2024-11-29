"""Select platform for Omada."""
import logging
from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .helpers import OmadaCoordinatorEntity
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

_SELECTS = {}  # Store select entities globally

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    """Set up select entities."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    api = hass.data[DOMAIN][entry.entry_id]["api"]
    entry_id = entry.entry_id  # Get the entry_id

    @callback
    def async_add_selects():
        """Add select entities."""
        new_selects = []

        # Add LED Setting select entities for AP devices
        if "devices" in coordinator.data:
            for device in coordinator.data["devices"]:
                if device.get("type") == "ap":
                    device_mac = device.get("mac")
                    unique_id = f"{DOMAIN}_{entry_id}_device_{device_mac}_led_setting"

                    if unique_id in _SELECTS:
                        continue  # Skip if entity already exists

                    select = OmadaLEDSettingSelect(coordinator, api, device, entry_id)
                    _SELECTS[unique_id] = select
                    new_selects.append(select)

        if new_selects:
            async_add_entities(new_selects)

    coordinator.async_add_listener(async_add_selects)
    async_add_selects()

class OmadaLEDSettingSelect(OmadaCoordinatorEntity, SelectEntity):
    """Representation of an Omada LED Setting select entity."""

    def __init__(self, coordinator, api, device, entry_id):
        """Initialize the select entity."""
        super().__init__(coordinator)
        self._api = api
        self._device = device
        self._device_mac = device.get("mac")
        device_name = device.get("name", self._device_mac)

        self._attr_name = f"{device_name} LED Setting"
        self._attr_unique_id = f"{DOMAIN}_{entry_id}_device_{self._device_mac}_led_setting"
        self._attr_icon = "mdi:led-on"
        self._attr_options = ["Off", "On", "Site Settings"]

        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"device_{self._device_mac}")},
            "name": device_name,
            "manufacturer": "TP-Link",
            "model": device.get("model", "Omada Device"),
            "sw_version": device.get("firmwareVersion", "Unknown"),
        }

    @property
    def current_option(self) -> str:
        """Return the current selected option."""
        device_data = self.coordinator.data.get("ap_data", {}).get(self._device_mac)
        if device_data:
            led_setting = device_data.get("ledSetting", 2)
            if led_setting == 0:
                return "Off"
            elif led_setting == 1:
                return "On"
            else:
                return "Site Settings"
        return None

    async def async_select_option(self, option: str) -> None:
        """Change the selected option."""
        _LOGGER.info(f"selected option: %s", option)
        if option == "Site Settings":
            led_setting = 2
        else:
            led_setting = self._attr_options.index(option)
        await self._update_led_setting(led_setting)

    async def _update_led_setting(self, setting: int) -> None:
        """Update the LED setting."""
        try:
            payload = {"ledSetting": setting}

            _LOGGER.info("Updating LED setting for device %s with payload: %s",
                        self._device_mac, payload)

            success = await self.hass.async_add_executor_job(
                self._api.update_device_ssid_overrides,
                self._device_mac,
                payload
            )

            if not success:
                _LOGGER.error("Failed to update LED setting for device %s",
                            self._device_mac)
                raise ValueError(f"Failed to update LED setting for device {self._device_mac}")

            _LOGGER.debug("Successfully updated LED setting for device %s",
                        self._device_mac)
            await self.coordinator.async_request_refresh()

        except Exception as error:
            _LOGGER.error("Error occurred while updating LED setting: %s", str(error))
            raise
