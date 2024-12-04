"""Helper classes for Omada integration."""
import re
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.core import callback

def standardize_mac(mac: str) -> str:
    """Standardize MAC address format."""
    # Remove any separators and convert to lowercase
    clean_mac = re.sub('[.:-]', '', mac.lower())
    # Insert colons every two characters
    return ':'.join(clean_mac[i:i+2] for i in range(0, 12, 2))

class OmadaCoordinatorEntity(CoordinatorEntity):
    """Base class for Omada entities."""

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        """Run when entity is added to registry."""
        await super().async_added_to_hass()
        self.async_on_remove(
            self.coordinator.async_add_listener(self._handle_coordinator_update)
        )

def is_valid_value(value):
    """Check if a value should be considered valid for display."""
    if value is None:
        return False

    if isinstance(value, str):
        return bool(value.strip()) and "Unknown" not in value

    if isinstance(value, (int, float)):
        return True

    if isinstance(value, bool):
        return True

    return bool(value)
