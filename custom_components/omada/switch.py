"""Switch platform for Omada Controller."""
from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
import asyncio

from .const import (
    DOMAIN,
    DEVICE_TYPE_NAMES,
)

import logging

_LOGGER = logging.getLogger(__name__)

class OmadaBaseSwitch(CoordinatorEntity, SwitchEntity):
    """Base class for Omada switches."""

    _attr_has_entity_name = False

    def __init__(self, coordinator, device_data, device_type, rule_type, switch_type):
        """Initialize the switch."""
        super().__init__(coordinator)
        self._device_data = device_data
        self._device_type = device_type
        self._rule_type = rule_type
        self._switch_type = switch_type
        self.entity_category = EntityCategory.CONFIG

        # Get device type name
        if isinstance(device_type, int):
            device_type_name = DEVICE_TYPE_NAMES.get(device_type, str(device_type))
        else:
            device_type_name = str(device_type).capitalize()

        # Generate device name and ID
        if "name" in device_data:
            self._device_name = device_data["name"]
            self._device_id = f"{device_data['name']}_{device_type}"
        elif "policyName" in device_data:
            self._device_name = device_data["policyName"]
            self._device_id = f"{device_data['policyName']}_{device_type}"
        else:
            self._device_name = str(device_data.get('id', ''))
            self._device_id = f"{device_type}_{device_data.get('id', '')}"

        # Create unique IDs for device and entity
        self._device_unique_id = f"omada_{self._rule_type}_{self._device_id}"
        self._attr_unique_id = f"{self._device_unique_id}_{switch_type}"

        # Set entity name
        self._attr_name = switch_type

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information about this entity."""
        # Get device type name for model
        if isinstance(self._device_type, int):
            device_type_name = DEVICE_TYPE_NAMES.get(self._device_type, str(self._device_type))
        else:
            device_type_name = str(self._device_type).capitalize()

        # Format model name based on rule type
        if self._rule_type == "url_filter":
            # Convert 'ap' to 'EAP' for URL filtering
            if device_type_name.lower() == 'ap':
                model_name = f"Omada EAP URL-Filtering"
            else:
                model_name = f"Omada {device_type_name} URL-Filtering"
        else:
            model_name = f"Omada {device_type_name} {self._rule_type.upper()}"

        return DeviceInfo(
            identifiers={(DOMAIN, self._device_unique_id)},
            name=self._device_name,
            manufacturer="TP-Link",
            model=model_name,
            via_device=(DOMAIN, "omada"),
        )

    def _get_updated_data(self):
        """Get the latest data for this rule."""
        if self._rule_type == "acl":
            for rule in self.coordinator.data["acl_rules"].get(self._device_type, []):
                if (
                    rule.get("id") == self._device_data.get("id") or
                    (
                        "name" in rule and
                        "name" in self._device_data and
                        rule["name"] == self._device_data["name"]
                    )
                ):
                    return rule
        elif self._rule_type == "url_filter":
            for rule in self.coordinator.data["url_filters"].get(self._device_type, []):
                if (
                    rule.get("id") == self._device_data.get("id") or
                    (
                        "name" in rule and
                        "name" in self._device_data and
                        rule["name"] == self._device_data["name"]
                    )
                ):
                    return rule
        return None

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if updated_data := self._get_updated_data():
            _LOGGER.debug(
                "Updating switch state for %s with data: %s",
                self._device_name,
                updated_data
            )
            self._device_data = updated_data
            self.async_write_ha_state()
        else:
            _LOGGER.warning(
                "Could not find updated data for %s rule %s in coordinator data",
                self._rule_type,
                self._device_name
            )


    async def _update_rule_state(self, enable: bool) -> None:
        """Update the rule state."""
        try:
            # Create payload based on current device data
            payload = dict(self._device_data)
            payload["status"] = enable

            # Make sure we have the required fields
            if self._rule_type == "acl":
                payload.update({
                    "type": self._device_type,
                    "siteId": self.coordinator.api.site_id,
                })
            else:  # url_filter
                payload.update({
                    "type": self._device_type,  # "gateway" or "ap"
                    "siteId": self.coordinator.api.site_id,
                })

            # Remove any None values from payload
            payload = {k: v for k, v in payload.items() if v is not None}

            _LOGGER.debug("Updating %s rule %s with payload: %s",
                         self._rule_type, self._device_name, payload)

            # Make the API call
            if self._rule_type == "acl":
                success = await self.hass.async_add_executor_job(
                    self.coordinator.api.update_acl_rule,
                    self._device_data["id"],
                    payload
                )
            else:  # url_filter
                success = await self.hass.async_add_executor_job(
                    self.coordinator.api.update_url_filter,
                    self._device_data["id"],
                    payload
                )

            if success:
                # Update local state immediately
                self._device_data["status"] = enable
                self.async_write_ha_state()

                # Schedule a delayed update after 1 second
                async def delayed_update():
                    await asyncio.sleep(1)
                    await self.coordinator.async_refresh()

                # Create and start the delayed update task
                self.hass.async_create_task(delayed_update())

            else:
                _LOGGER.error("Failed to update %s rule state for %s",
                            self._rule_type, self._device_name)

        except Exception as err:
            _LOGGER.error("Failed to update %s rule state for %s: %s",
                         self._rule_type, self._device_name, err)
            raise

class OmadaEnabledSwitch(OmadaBaseSwitch):
    """Representation of an Omada enabled switch."""

    def __init__(self, coordinator, device_data, device_type, rule_type):
        """Initialize the enabled switch."""
        super().__init__(coordinator, device_data, device_type, rule_type, "Enabled")

    @property
    def is_on(self) -> bool:
        """Return true if the switch is on."""
        return bool(self._device_data.get("status", False))

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the switch on."""
        await self._update_rule_state(True)

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the switch off."""
        await self._update_rule_state(False)

class OmadaDisabledSwitch(OmadaBaseSwitch):
    """Representation of an Omada disabled switch."""

    def __init__(self, coordinator, device_data, device_type, rule_type):
        """Initialize the disabled switch."""
        super().__init__(coordinator, device_data, device_type, rule_type, "Disabled")

    @property
    def is_on(self) -> bool:
        """Return true if the switch is on (rule is disabled)."""
        return not bool(self._device_data.get("status", False))

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the switch on (disable the rule)."""
        await self._update_rule_state(False)

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the switch off (enable the rule)."""
        await self._update_rule_state(True)

async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> bool:
    """Set up switches from a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities = []

    # Create switches for ACL rules
    for device_type, rules in coordinator.data["acl_rules"].items():
        for rule in rules:
            entities.extend([
                OmadaEnabledSwitch(coordinator, rule, device_type, "acl"),
                OmadaDisabledSwitch(coordinator, rule, device_type, "acl")
            ])

    # Create switches for URL filters
    for filter_type, filters in coordinator.data["url_filters"].items():
        for filter_rule in filters:
            entities.extend([
                OmadaEnabledSwitch(coordinator, filter_rule, filter_type, "url_filter"),
                OmadaDisabledSwitch(coordinator, filter_rule, filter_type, "url_filter")
            ])

    async_add_entities(entities)
    return True