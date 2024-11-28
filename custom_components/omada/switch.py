"""Switch platform for Test HA Omada."""
import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .helpers import OmadaCoordinatorEntity
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up switches for ACL rules."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]["coordinator"]
    api = hass.data[DOMAIN][config_entry.entry_id]["api"]

    switches = {}

    @callback
    def async_add_switches():
        """Add new switches."""
        new_switches = []
        current_rules = set()

        for device_type in ["gateway", "switch", "eap"]:
            if device_type not in coordinator.data["acl_rules"]:
                continue

            for rule in coordinator.data["acl_rules"][device_type]:
                rule_id = rule.get("id")
                if not rule_id:
                    continue

                identifier = f"{device_type}_{rule_id}"
                current_rules.add(identifier)

                if identifier not in switches:
                    rule_name = rule.get("name", rule_id)
                    device_name = f"Omada ACL {device_type.capitalize()} Rule - {rule_name}"
                    switch = OmadaACLRuleSwitch(coordinator, api, rule, device_type, device_name)
                    switches[identifier] = switch
                    new_switches.append(switch)

        if new_switches:
            async_add_entities(new_switches)

    coordinator.async_add_listener(async_add_switches)
    async_add_switches()

class OmadaACLRuleSwitch(OmadaCoordinatorEntity, SwitchEntity):
    """Representation of an ACL rule switch."""

    def __init__(self, coordinator, api, rule, device_type, device_name):
        """Initialize the switch."""
        super().__init__(coordinator)
        self._api = api
        self._rule = rule
        self._device_type = device_type
        self._rule_id = rule.get("id")
        self._attr_name = f"{device_name} Status"
        self._attr_unique_id = f"acl_rule_{device_type}_{self._rule_id}_status"

        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"acl_rule_{device_type}_{self._rule_id}")},
            "name": device_name,
            "manufacturer": "TP-Link",
            "model": f"Omada ACL {device_type.capitalize()} Rule",
        }

    @property
    def is_on(self) -> bool:
        """Return true if the switch is on."""
        rules = self.coordinator.data["acl_rules"].get(self._device_type, [])
        return any(rule.get("id") == self._rule_id and rule.get("status", False)
                  for rule in rules)

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn on the switch."""
        await self._update_rule_status(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off the switch."""
        await self._update_rule_status(False)

    async def _update_rule_status(self, status: bool) -> None:
        """Update the ACL rule status."""
        try:
            current_rule = None
            for rule in self.coordinator.data["acl_rules"].get(self._device_type, []):
                if rule.get("id") == self._rule_id:
                    current_rule = dict(rule)
                    break

            if not current_rule:
                raise ValueError(f"Rule {self._rule_id} not found")

            current_rule["status"] = status

            success = await self.hass.async_add_executor_job(
                self._api.update_acl_rule,
                self._rule_id,
                current_rule
            )

            if not success:
                raise ValueError(f"Failed to update rule {self._rule_id}")

            await self.coordinator.async_request_refresh()

        except Exception as error:
            _LOGGER.error("Failed to update ACL rule status: %s", error)
            raise