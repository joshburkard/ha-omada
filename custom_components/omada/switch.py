"""Switch platform for Test HA Omada."""
import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.components.select import SelectEntity
from homeassistant.helpers.entity_registry import async_get as er_async_get
from homeassistant.helpers.entity_registry import RegistryEntryDisabler

from .helpers import OmadaCoordinatorEntity, standardize_mac
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up switches."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]["coordinator"]
    api = hass.data[DOMAIN][config_entry.entry_id]["api"]
    entity_registry = er_async_get(hass)

    @callback
    def async_add_switches():
        """Add new switches."""
        new_switches = []
        tracked_entities = coordinator.tracked_entities["switch"]

        # Add Client Block switches
        if "clients" in coordinator.data:
            for client in coordinator.data["clients"]:
                client_mac = client.get("mac")
                if not client_mac:
                    continue

                switch_id = f"client_{client_mac}_blocked"
                if switch_id not in tracked_entities:
                    _LOGGER.debug("Adding new client block switch: %s", switch_id)
                    switch = OmadaClientBlockSwitch(
                        coordinator,
                        api,
                        client
                    )
                    tracked_entities[switch_id] = switch
                    new_switches.append(switch)

        # Add ACL Rule switches
        for device_type in ["gateway", "switch", "eap"]:
            if device_type in coordinator.data.get("acl_rules", {}):
                for rule in coordinator.data["acl_rules"][device_type]:
                    rule_id = rule.get("id")
                    if not rule_id:
                        continue

                    identifier = f"{device_type}_{rule_id}"
                    if identifier not in tracked_entities:
                        _LOGGER.debug("Adding new ACL rule switch: %s", identifier)
                        rule_name = rule.get("name", rule_id)
                        if device_type == 'gateway':
                            device_name = f"Omada Gateway ACL Rule - {rule_name}"
                        elif device_type == 'switch':
                            device_name = f"Omada Switch ACL Rule - {rule_name}"
                        else:
                            device_name = f"Omada EAP ACL Rule - {rule_name}"

                        switch = OmadaACLRuleSwitch(
                            coordinator,
                            api,
                            rule,
                            device_type,
                            device_name
                        )
                        tracked_entities[identifier] = switch
                        new_switches.append(switch)

        # Add URL Filter switches
        for filter_type in ["gateway", "ap"]:
            if filter_type in coordinator.data.get("url_filters", {}):
                for rule in coordinator.data["url_filters"][filter_type]:
                    rule_id = rule.get("id")
                    if not rule_id:
                        continue

                    identifier = f"{filter_type}_url_{rule_id}"
                    if identifier not in tracked_entities:
                        _LOGGER.debug("Adding new URL filter switch: %s", identifier)
                        rule_name = rule.get("name", rule_id)
                        device_name = f"Omada {'Gateway' if filter_type == 'gateway' else 'EAP'} URL Filter - {rule_name}"
                        switch = OmadaURLFilterSwitch(
                            coordinator,
                            api,
                            rule,
                            filter_type,
                            device_name
                        )
                        tracked_entities[identifier] = switch
                        new_switches.append(switch)

        # Add SSID Override switches
        if "devices" in coordinator.data and "ssid_overrides" in coordinator.data:
            for device in coordinator.data["devices"]:
                if device.get("type") == "ap":
                    device_mac = device.get("mac")
                    device_overrides = coordinator.data["ssid_overrides"].get(device_mac, [])

                    for override in device_overrides:
                        ssid_name = override.get("ssid")
                        if not ssid_name:
                            continue

                        switch_id = f"device_{device_mac}_ssid_{ssid_name}"
                        if switch_id not in tracked_entities:
                            _LOGGER.debug("Adding new SSID override switch: %s", switch_id)
                            switch = OmadaSSIDOverrideSwitch(
                                coordinator,
                                api,
                                device,
                                ssid_name
                            )
                            tracked_entities[switch_id] = switch
                            new_switches.append(switch)

        # Add Radio switches for AP devices
        if "devices" in coordinator.data:
            for device in coordinator.data["devices"]:
                if device.get("type") == "ap":
                    device_mac = device.get("mac")

                    for radio_type in ["2g", "5g"]:
                        switch_id = f"device_{device_mac}_radio_{radio_type}"
                        if switch_id not in tracked_entities:
                            switch = OmadaRadioSwitch(
                                coordinator,
                                api,
                                device,
                                radio_type
                            )
                            tracked_entities[switch_id] = switch
                            new_switches.append(switch)

        if new_switches:
            _LOGGER.debug("Adding %d new switches", len(new_switches))
            async_add_entities(new_switches)

    coordinator.async_add_listener(async_add_switches)
    async_add_switches()

class OmadaClientBlockSwitch(OmadaCoordinatorEntity, SwitchEntity):
    """Switch to control client blocking status."""

    def __init__(self, coordinator, api, client):
        """Initialize the switch."""
        super().__init__(coordinator)
        self._api = api
        self._client = client
        self._mac = standardize_mac(client['mac'])
        client_name = client.get('name', self._mac)

        self._attr_name = f"{client_name} Blocked"
        self._attr_unique_id = f"client_{self._mac}_blocked"
        self._attr_icon = "mdi:wifi-off"

        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"client_{self._mac}")},
            "name": client_name,
            "manufacturer": client.get("manufacturer", "TP-Link"),
            "model": "Omada Client",
            "sw_version": client.get("os", "Unknown"),
            "connections": {("mac", self._mac)}
        }

    def _format_mac_for_api(self, mac: str) -> str:
        """Format MAC address for API calls (00-00-00-00-00-00)."""
        # Remove any existing separators and convert to uppercase
        clean_mac = mac.replace(":", "").replace("-", "").upper()
        # Insert hyphens every two characters
        return "-".join(clean_mac[i:i+2] for i in range(0, 12, 2))

    @property
    def is_on(self) -> bool:
        """Return true if client is blocked."""
        for client in self.coordinator.data["clients"]:
            if standardize_mac(client["mac"]) == self._mac:
                return client.get("block", False)
        return False

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Block the client."""
        try:
            # Format MAC address for API call
            api_mac = self._format_mac_for_api(self._mac)
            success = await self.hass.async_add_executor_job(
                self._api.block_client,
                api_mac
            )

            if success:
                await self.coordinator.async_request_refresh()
            else:
                _LOGGER.error("Failed to block client %s", api_mac)

        except Exception as error:
            _LOGGER.error("Error blocking client %s: %s", self._mac, str(error))
            raise

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Unblock the client."""
        try:
            # Format MAC address for API call
            api_mac = self._format_mac_for_api(self._mac)
            success = await self.hass.async_add_executor_job(
                self._api.unblock_client,
                api_mac
            )

            if success:
                await self.coordinator.async_request_refresh()
            else:
                _LOGGER.error("Failed to unblock client %s", api_mac)

        except Exception as error:
            _LOGGER.error("Error unblocking client %s: %s", self._mac, str(error))
            raise

class OmadaACLRuleSwitch(OmadaCoordinatorEntity, SwitchEntity):
    """Switch for ACL rule status."""

    def __init__(self, coordinator, api, rule, device_type, device_name):
        """Initialize the switch."""
        super().__init__(coordinator)
        self._api = api
        self._rule = rule
        self._device_type = device_type
        self._rule_id = rule.get("id")
        self._attr_name = f"{device_name} Status"
        self._attr_unique_id = f"acl_rule_{device_type}_{self._rule_id}_status"

        if device_type == 'gateway':
            model_name = 'Omada Gateway ACL Rule'
        elif device_type == 'switch':
            model_name = 'Omada Switch ACL Rule'
        else:
            model_name = 'Omada EAP ACL Rule'

        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"acl_rule_{device_type}_{self._rule_id}")},
            "name": device_name,
            "manufacturer": "TP-Link",
            "model": model_name,
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

class OmadaURLFilterSwitch(OmadaCoordinatorEntity, SwitchEntity):
    """Switch for URL filter status."""

    def __init__(self, coordinator, api, rule, filter_type, device_name):
        """Initialize the switch."""
        super().__init__(coordinator)
        self._api = api
        self._rule = rule
        self._filter_type = filter_type
        self._rule_id = rule.get("id")
        self._attr_name = f"{device_name} Status"
        self._attr_unique_id = f"url_filter_{filter_type}_{self._rule_id}_status"

        model_name = f"Omada {'Gateway' if filter_type == 'gateway' else 'EAP'} URL Filter"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"url_filter_{filter_type}_{self._rule_id}")},
            "name": device_name,
            "manufacturer": "TP-Link",
            "model": model_name,
        }

    @property
    def is_on(self) -> bool:
        """Return true if the switch is on."""
        rules = self.coordinator.data["url_filters"].get(self._filter_type, [])
        return any(rule.get("id") == self._rule_id and rule.get("status", False)
                  for rule in rules)

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn on the switch."""
        await self._update_filter_status(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off the switch."""
        await self._update_filter_status(False)

    async def _update_filter_status(self, status: bool) -> None:
        """Update the URL filter status."""
        try:
            current_rule = None
            for rule in self.coordinator.data["url_filters"].get(self._filter_type, []):
                if rule.get("id") == self._rule_id:
                    current_rule = dict(rule)
                    break

            if not current_rule:
                raise ValueError(f"Rule {self._rule_id} not found")

            current_rule["status"] = status
            # Ensure required fields are in payload
            current_rule.setdefault("urls", [])
            current_rule.setdefault("sourceIds", [])

            success = await self.hass.async_add_executor_job(
                self._api.update_url_filter,
                self._rule_id,
                current_rule
            )

            if not success:
                raise ValueError(f"Failed to update URL filter {self._rule_id}")

            await self.coordinator.async_request_refresh()

        except Exception as error:
            _LOGGER.error("Failed to update URL filter status: %s", error)
            raise

class OmadaSSIDOverrideSwitch(OmadaCoordinatorEntity, SwitchEntity):
    """Switch for SSID Override control."""

    def __init__(self, coordinator, api, device, ssid_name):
        """Initialize the switch."""
        super().__init__(coordinator)
        self._api = api
        self._device = device
        self._device_mac = device.get("mac")
        self._ssid_name = ssid_name
        device_name = device.get("name", self._device_mac)

        self._attr_name = f"{device_name} SSID {ssid_name}"
        self._attr_unique_id = f"device_{self._device_mac}_ssid_{ssid_name}"
        self._attr_icon = "mdi:wifi"

        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"device_{self._device_mac}")},
            "name": device_name,
            "manufacturer": "TP-Link",
            "model": device.get("model", "Omada Device"),
            "sw_version": device.get("firmwareVersion", "Unknown"),
        }

    @property
    def is_on(self) -> bool:
        """Return true if the SSID is enabled."""
        ssid_overrides = self.coordinator.data["ssid_overrides"].get(self._device_mac, [])
        for override in ssid_overrides:
            if override.get("ssid") == self._ssid_name:
                return override.get("ssidEnable", False)
        return False

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Enable the SSID."""
        await self._update_ssid_status(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Disable the SSID."""
        await self._update_ssid_status(False)

    async def _update_ssid_status(self, status: bool) -> None:
        """Update the SSID enable status."""
        try:
            device_overrides = self.coordinator.data["ssid_overrides"].get(self._device_mac, [])
            updated_overrides = []
            wlanId = None

            for override in device_overrides:
                override_copy = dict(override)
                if override.get("ssid") == self._ssid_name:
                    override_copy["ssidEnable"] = status
                    if "wlanId" in override:
                        wlanId = override["wlanId"]

                # Ensure all required fields are present
                if "enable" not in override_copy:
                    override_copy["enable"] = False
                if "hidePwd" not in override_copy:
                    override_copy["hidePwd"] = False
                if "security" not in override_copy:
                    override_copy["security"] = 3
                if "supportBands" not in override_copy:
                    override_copy["supportBands"] = [0]
                if "vlanEnable" not in override_copy:
                    override_copy["vlanEnable"] = False
                if "vlanId" not in override_copy:
                    override_copy["vlanId"] = 1

                updated_overrides.append(override_copy)

            if not updated_overrides:
                raise ValueError(f"SSID {self._ssid_name} not found for device {self._device_mac}")

            # If wlanId wasn't found in overrides, try to find it in ssids list
            if not wlanId:
                for ssid in self.coordinator.data["ssids"]:  # ssids is now a list
                    if ssid.get("name") == self._ssid_name:
                        wlanId = ssid.get("wlanId")
                        break

            if not wlanId:
                raise ValueError(f"Could not find wlanId for SSID {self._ssid_name}")

            payload = {
                "ssidOverrides": updated_overrides,
                "wlanId": wlanId
            }

            success = await self.hass.async_add_executor_job(
                self._api.update_device_ssid_overrides,
                self._device_mac,
                payload
            )

            if not success:
                raise ValueError(f"Failed to update SSID override for {self._ssid_name}")

            await self.coordinator.async_request_refresh()

        except Exception as error:
            _LOGGER.error("Failed to update SSID override status: %s", error)
            raise

class OmadaRadioSwitch(OmadaCoordinatorEntity, SwitchEntity):
    """Switch for AP radio control."""

    def __init__(self, coordinator, api, device, radio_type):
        """Initialize the switch."""
        super().__init__(coordinator)
        self._api = api
        self._device = device
        self._device_mac = device.get("mac")
        self._radio_type = radio_type
        device_name = device.get("name", self._device_mac)
        radio_name = "2.4GHz Radio" if radio_type == "2g" else "5GHz Radio"

        self._attr_name = f"{device_name} {radio_name}"
        self._attr_unique_id = f"device_{self._device_mac}_radio_{radio_type}"
        self._attr_icon = "mdi:antenna"

        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"device_{self._device_mac}")},
            "name": device_name,
            "manufacturer": "TP-Link",
            "model": device.get("model", "Omada Device"),
            "sw_version": device.get("firmwareVersion", "Unknown"),
        }

    @property
    def is_on(self) -> bool:
        """Return true if the radio is enabled."""
        device_data = self.coordinator.data.get("ap_data", {}).get(self._device_mac)
        _LOGGER.debug(f"is_on datas received for %s: %s", self._device_mac, device_data )
        setting_key = "radioSetting2g" if self._radio_type == "2g" else "radioSetting5g"
        return device_data.get(setting_key, {})

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn on the radio."""
        await self._update_radio_status(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off the radio."""
        await self._update_radio_status(False)

    async def _update_radio_status(self, status: bool) -> None:
        """Update the radio status."""
        try:
            payload = {
                "radioSetting2g" if self._radio_type == "2g" else "radioSetting5g": {
                    "radioEnable": status
                }
            }

            _LOGGER.debug("Updating %s radio status for device %s with payload: %s",
                        self._radio_type, self._device_mac, payload)

            success = await self.hass.async_add_executor_job(
                self._api.update_device_radio,
                self._device_mac,
                payload
            )

            if not success:
                _LOGGER.error("Failed to update %s radio status for device %s",
                            self._radio_type, self._device_mac)
                raise ValueError(f"Failed to update {self._radio_type} radio status for device {self._device_mac}")

            _LOGGER.debug("Successfully updated %s radio status for device %s",
                        self._radio_type, self._device_mac)
            await self.coordinator.async_request_refresh()

        except Exception as error:
            _LOGGER.error("Error occurred while updating radio status: %s", str(error))
            raise
