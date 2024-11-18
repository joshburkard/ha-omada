"""Switch platform for Omada Controller."""
from __future__ import annotations

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    DOMAIN,
    DEVICE_TYPE_NAMES,
)

import logging

_LOGGER = logging.getLogger(__name__)

class OmadaBaseSwitch(CoordinatorEntity, SwitchEntity):
    """Base class for Omada switches."""

    _attr_has_entity_name = True

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
        if isinstance(self._device_type, int):
            device_type_name = DEVICE_TYPE_NAMES.get(self._device_type, str(self._device_type))
        else:
            device_type_name = str(self._device_type).capitalize()

        # Format model name based on rule type
        if self._rule_type == "url_filter":
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
        data = None
        if self._rule_type == "acl":
            rules = self.coordinator.data.get("acl_rules", {}).get(self._device_type, [])
            for rule in rules:
                if (rule.get("id") == self._device_data.get("id") or
                        ("name" in rule and "name" in self._device_data and
                         rule["name"] == self._device_data["name"])):
                    data = rule
                    break
        elif self._rule_type == "url_filter":
            rules = self.coordinator.data.get("url_filters", {}).get(self._device_type, [])
            for rule in rules:
                if (rule.get("id") == self._device_data.get("id") or
                        ("name" in rule and "name" in self._device_data and
                         rule["name"] == self._device_data["name"])):
                    data = rule
                    break

        if not data and hasattr(self.coordinator, 'trigger_removal'):
            self.coordinator.trigger_removal(self.entity_id, self._device_unique_id)

        return data

    async def async_will_remove_from_hass(self) -> None:
        """Handle entity being removed from Home Assistant."""
        await super().async_will_remove_from_hass()
        if hasattr(self.coordinator, 'trigger_removal'):
            await self.coordinator.trigger_removal(self.entity_id, self._device_unique_id)

class OmadaEnabledSwitch(OmadaBaseSwitch):
    """Representation of an Omada enabled switch."""

    def __init__(self, coordinator, device_data, device_type, rule_type):
        """Initialize the enabled switch."""
        super().__init__(coordinator, device_data, device_type, rule_type, "enabled")

    @property
    def is_on(self) -> bool:
        """Return true if the switch is on."""
        if data := self._get_updated_data():
            return bool(data.get("status", False))
        return False

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the switch on."""
        await self._update_rule_state(True)

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the switch off."""
        await self._update_rule_state(False)

    async def _update_rule_state(self, enable: bool) -> None:
        """Update the rule state."""
        if data := self._get_updated_data():
            payload = dict(data)
            payload["status"] = enable

            if self._rule_type == "acl":
                await self.hass.async_add_executor_job(
                    self.coordinator.api.update_acl_rule,
                    data["id"],
                    payload
                )
            else:  # url_filter
                await self.hass.async_add_executor_job(
                    self.coordinator.api.update_url_filter,
                    data["id"],
                    payload
                )

            await self.coordinator.async_refresh()

class OmadaDisabledSwitch(OmadaBaseSwitch):
    """Representation of an Omada disabled switch."""

    def __init__(self, coordinator, device_data, device_type, rule_type):
        """Initialize the disabled switch."""
        super().__init__(coordinator, device_data, device_type, rule_type, "disabled")

    @property
    def is_on(self) -> bool:
        """Return true if the switch is on (rule is disabled)."""
        if data := self._get_updated_data():
            return not bool(data.get("status", False))
        return True

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the switch on (disable the rule)."""
        await self._update_rule_state(False)

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the switch off (enable the rule)."""
        await self._update_rule_state(True)

    async def _update_rule_state(self, enable: bool) -> None:
        """Update the rule state."""
        if data := self._get_updated_data():
            payload = dict(data)
            payload["status"] = enable

            if self._rule_type == "acl":
                await self.hass.async_add_executor_job(
                    self.coordinator.api.update_acl_rule,
                    data["id"],
                    payload
                )
            else:  # url_filter
                await self.hass.async_add_executor_job(
                    self.coordinator.api.update_url_filter,
                    data["id"],
                    payload
                )

            await self.coordinator.async_refresh()

async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> bool:
    """Set up switches from a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]

    entities = []

    # Create switches for ACL rules
    _LOGGER.debug("Processing ACL rules")
    for device_type, rules in coordinator.data.get("acl_rules", {}).items():
        _LOGGER.debug("Found ACL rules for device type %s: %s", device_type, rules)
        if isinstance(rules, list):
            for rule in rules:
                _LOGGER.debug("Creating switches for ACL rule: %s", rule)
                entities.extend([
                    OmadaEnabledSwitch(coordinator, rule, device_type, "acl"),
                    OmadaDisabledSwitch(coordinator, rule, device_type, "acl")
                ])

    # Create switches for URL filters
    _LOGGER.debug("Processing URL filters")
    for filter_type, filters in coordinator.data.get("url_filters", {}).items():
        _LOGGER.debug("Found URL filters for type %s: %s", filter_type, filters)
        if isinstance(filters, list):
            for filter_rule in filters:
                _LOGGER.debug("Creating switches for URL filter: %s", filter_rule)
                entities.extend([
                    OmadaEnabledSwitch(coordinator, filter_rule, filter_type, "url_filter"),
                    OmadaDisabledSwitch(coordinator, filter_rule, filter_type, "url_filter")
                ])

    if entities:
        _LOGGER.debug("Adding %d switch entities", len(entities))
        async_add_entities(entities)

    return True