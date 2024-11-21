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

    def __init__(self, coordinator, device_data, device_type, rule_type):
        """Initialize the switch."""
        super().__init__(coordinator)
        self._device_data = device_data
        self._device_type = device_type
        self._rule_type = rule_type
        self.entity_category = EntityCategory.CONFIG

        # Keep original case for display name
        if "name" in device_data:
            self._device_name = device_data["name"]
            device_name_lower = self._device_name.lower()
        elif "policyName" in device_data:
            self._device_name = device_data["policyName"]
            device_name_lower = self._device_name.lower()
        else:
            self._device_name = str(device_data.get('id', ''))
            device_name_lower = self._device_name.lower()

        # Sanitize device name for entity_id (lowercase)
        sanitized_name = device_name_lower.replace(' ', '_').replace('-', '_')

        # Set entity_id based on rule_type
        if rule_type == "acl":
            # Map device type number to string for ACL rules
            type_map = {0: "gateway", 1: "switch", 2: "eap"}
            device_type_str = type_map.get(device_type, "unknown")
            self.entity_id = f"switch.om_aclrule_{device_type_str}_{sanitized_name}_enabled"
            self._device_unique_id = f"omada_acl_{device_type_str}_{sanitized_name}"
        elif rule_type == "url_filter":
            # For URL filters, device_type is already a string ('gateway' or 'ap')
            self.entity_id = f"switch.om_urlfilter_{device_type}_{sanitized_name}_enabled"
            self._device_unique_id = f"omada_url_filter_{device_type}_{sanitized_name}"

        self._attr_unique_id = f"{self._device_unique_id}_enabled"
        self._attr_name = "Enabled"

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

async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> bool:
    """Set up switches from a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities = []

    @callback
    def update_entities():
        """Update entities with new ACL rules and URL filters."""
        new_entities = []

        # Create switches for ACL rules
        for device_type, rules in coordinator.data.get("acl_rules", {}).items():
            if isinstance(rules, list):
                for rule in rules:
                    # Check if switch already exists
                    switch_unique_id = f"omada_acl_{rule.get('name')}_{device_type}_enabled"
                    if not any(entity.unique_id == switch_unique_id for entity in entities):
                        _LOGGER.debug("Creating new switch for ACL rule: %s", rule.get('name'))
                        new_entities.append(OmadaEnabledSwitch(coordinator, rule, device_type, "acl"))

        # Create switches for URL filters
        for filter_type, filters in coordinator.data.get("url_filters", {}).items():
            if isinstance(filters, list):
                for filter_rule in filters:
                    # Check if switch already exists
                    switch_unique_id = f"omada_url_filter_{filter_rule.get('name')}_{filter_type}_enabled"
                    if not any(entity.unique_id == switch_unique_id for entity in entities):
                        _LOGGER.debug("Creating new switch for URL filter: %s", filter_rule.get('name'))
                        new_entities.append(OmadaEnabledSwitch(coordinator, filter_rule, filter_type, "url_filter"))

        # Add any new entities found
        if new_entities:
            entities.extend(new_entities)
            async_add_entities(new_entities)

    coordinator.async_add_listener(update_entities)
    update_entities()
    return True