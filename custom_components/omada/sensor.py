"""Sensor platform for Omada Controller."""
from homeassistant.components.sensor import SensorEntity, SensorDeviceClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.const import UnitOfTime

from .const import (
    DOMAIN,
    DEVICE_TYPE_NAMES,
)

import logging

_LOGGER = logging.getLogger(__name__)

class OmadaBaseSensor(CoordinatorEntity, SensorEntity):
    """Base class for Omada sensors."""

    _attr_has_entity_name = True

    def __init__(self, coordinator, device_data, device_type, rule_type, sensor_type):
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._device_data = device_data
        self._device_type = device_type
        self._rule_type = rule_type
        self._sensor_type = sensor_type
        self.entity_category = EntityCategory.DIAGNOSTIC

        # Generate device name and ID
        if isinstance(device_type, int):
            device_type_name = DEVICE_TYPE_NAMES.get(device_type, str(device_type))
        else:
            device_type_name = str(device_type).capitalize()

        # Generate device name and ID (without device type name)
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
        self._device_unique_id = f"omada_{rule_type}_{self._device_id}"
        self._attr_unique_id = f"{self._device_unique_id}_{sensor_type}"

        # Set entity name
        self._attr_name = sensor_type.replace('_', ' ').title()

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
                "Updating sensor state for %s with data: %s",
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

class OmadaTypeSensor(OmadaBaseSensor):
    """Sensor for Omada rule type."""

    def __init__(self, coordinator, device_data, device_type, rule_type):
        """Initialize the type sensor."""
        super().__init__(coordinator, device_data, device_type, rule_type, "type")

    @property
    def native_value(self):
        """Return the type."""
        if isinstance(self._device_type, int):
            return DEVICE_TYPE_NAMES.get(self._device_type, str(self._device_type))
        return self._device_type

    @property
    def extra_state_attributes(self):
        """Return additional state attributes."""
        return {
            "rule_type": self._rule_type,
            "raw_type": self._device_type
        }

class OmadaIndexSensor(OmadaBaseSensor):
    """Sensor for Omada rule index."""

    def __init__(self, coordinator, device_data, device_type, rule_type):
        """Initialize the index sensor."""
        super().__init__(coordinator, device_data, device_type, rule_type, "index")

    @property
    def native_value(self):
        """Return the index."""
        return self._device_data.get("index")

    @property
    def extra_state_attributes(self):
        """Return additional state attributes."""
        return {
            "rule_type": self._rule_type,
            "device_type": DEVICE_TYPE_NAMES.get(self._device_type, self._device_type)
        }

class OmadaProtocolSensor(OmadaBaseSensor):
    """Sensor for Omada rule protocols."""

    # Protocol mapping
    PROTOCOL_MAP = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        256: "ALL",
        # Add more protocol mappings as needed
    }

    def __init__(self, coordinator, device_data, device_type, rule_type):
        """Initialize the protocol sensor."""
        super().__init__(coordinator, device_data, device_type, rule_type, "protocols")

    def _format_protocol(self, protocol):
        """Convert protocol number to string representation."""
        if isinstance(protocol, str):
            return protocol
        return self.PROTOCOL_MAP.get(protocol, f"Protocol {protocol}")

    @property
    def native_value(self):
        """Return the protocols."""
        protocols = self._device_data.get("protocols", [])
        if isinstance(protocols, list):
            return ", ".join(self._format_protocol(p) for p in protocols)
        return self._format_protocol(protocols)

    @property
    def extra_state_attributes(self):
        """Return additional state attributes."""
        protocols = self._device_data.get("protocols", [])
        return {
            "rule_type": self._rule_type,
            "device_type": DEVICE_TYPE_NAMES.get(self._device_type, self._device_type),
            "raw_protocols": protocols,
            "protocol_names": [self._format_protocol(p) for p in protocols] if isinstance(protocols, list) else [self._format_protocol(protocols)]
        }

class OmadaPolicySensor(OmadaBaseSensor):
    """Sensor for Omada rule policy."""

    POLICY_MAP = {
        0: "Deny",
        1: "Permit"
    }

    def __init__(self, coordinator, device_data, device_type, rule_type):
        """Initialize the policy sensor."""
        super().__init__(coordinator, device_data, device_type, rule_type, "policy")

    @property
    def native_value(self):
        """Return the policy."""
        policy = self._device_data.get("policy")
        return self.POLICY_MAP.get(policy, f"Unknown ({policy})")

    @property
    def extra_state_attributes(self):
        """Return additional state attributes."""
        return {
            "rule_type": self._rule_type,
            "device_type": DEVICE_TYPE_NAMES.get(self._device_type, self._device_type),
            "raw_policy": self._device_data.get("policy")
        }

class OmadaDeviceSensor(CoordinatorEntity, SensorEntity):
    """Base sensor for Omada device information."""

    _attr_has_entity_name = True

    def __init__(self, coordinator, device_data, sensor_type):
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._device_data = device_data
        self._sensor_type = sensor_type
        self.entity_category = EntityCategory.DIAGNOSTIC

        # Clean up MAC address for ID
        self._device_mac = device_data.get("mac", "").replace(':', '').replace('-', '').lower()
        self._device_name = device_data.get("name", device_data.get("mac", "Unknown"))
        self._device_unique_id = f"omada_device_{self._device_mac}"
        self._attr_unique_id = f"{self._device_unique_id}_{sensor_type}"

        # Set entity name
        self._attr_name = sensor_type.replace('_', ' ').title()

        _LOGGER.debug(
            "Initializing device sensor %s for device %s",
            self._attr_name,
            self._device_name
        )

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._device_unique_id)},
            name=self._device_name,
            manufacturer="TP-Link",
            model="Omada Device",  # Fixed model name for all devices
            sw_version=self._device_data.get("firmwareVersion", "Unknown"),
            hw_version=self._device_data.get("hwVersion", "Unknown"),
            configuration_url=None,
        )

    def _get_updated_data(self):
        """Get the latest device data."""
        if not self.coordinator.data.get("devices", {}).get("data"):
            return None

        for device in self.coordinator.data["devices"]["data"]:
            if device.get("mac", "").replace(':', '').replace('-', '').lower() == self._device_mac:
                return device
        return None

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if updated_data := self._get_updated_data():
            self._device_data = updated_data
            self.async_write_ha_state()

class OmadaDeviceBasicSensor(OmadaDeviceSensor):
    """Sensor for basic device information."""

    def __init__(self, coordinator, device_data, sensor_type, attribute):
        """Initialize the sensor."""
        super().__init__(coordinator, device_data, sensor_type)
        self._attribute = attribute

    @property
    def native_value(self):
        """Return the state of the sensor."""
        return self._device_data.get(self._attribute)

class OmadaDeviceUptimeSensor(OmadaDeviceSensor):
    """Sensor for device uptime."""

    def __init__(self, coordinator, device_data):
        """Initialize the sensor."""
        super().__init__(coordinator, device_data, "uptime")
        self._attr_device_class = SensorDeviceClass.DURATION
        self._attr_native_unit_of_measurement = UnitOfTime.SECONDS

    @property
    def native_value(self):
        """Return the state of the sensor."""
        return self._device_data.get("uptimeLong")

    @property
    def extra_state_attributes(self):
        """Return additional state attributes."""
        return {
            "uptime_string": self._device_data.get("uptime")
        }

class OmadaClientSensor(CoordinatorEntity, SensorEntity):
    """Base sensor for Omada client information."""

    _attr_has_entity_name = True

    def __init__(self, coordinator, client_data, sensor_type):
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._client_data = client_data
        self._sensor_type = sensor_type
        self.entity_category = EntityCategory.DIAGNOSTIC

        # Clean up MAC address for ID
        self._client_mac = client_data.get("mac", "").replace(':', '').replace('-', '').lower()
        self._client_name = client_data.get("name", client_data.get("mac", "Unknown"))
        self._device_unique_id = f"omada_client_{self._client_mac}"
        self._attr_unique_id = f"{self._device_unique_id}_{sensor_type}"

        # Set entity name
        self._attr_name = sensor_type.replace('_', ' ').title()

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

    def _get_updated_data(self):
        """Get the latest client data."""
        if not self.coordinator.data.get("clients", {}).get("data"):
            return None

        for client in self.coordinator.data["clients"]["data"]:
            if client.get("mac", "").replace(':', '').replace('-', '').lower() == self._client_mac:
                return client
        return None

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if updated_data := self._get_updated_data():
            self._client_data = updated_data
            self.async_write_ha_state()

class OmadaClientBasicSensor(OmadaClientSensor):
    """Sensor for basic client information."""

    def __init__(self, coordinator, client_data, sensor_type, attribute):
        """Initialize the sensor."""
        super().__init__(coordinator, client_data, sensor_type)
        self._attribute = attribute

    @property
    def native_value(self):
        """Return the state of the sensor."""
        return self._client_data.get(self._attribute)

class OmadaClientUptimeSensor(OmadaClientSensor):
    """Sensor for client uptime."""

    def __init__(self, coordinator, client_data):
        """Initialize the sensor."""
        super().__init__(coordinator, client_data, "uptime")
        self._attr_device_class = SensorDeviceClass.DURATION
        self._attr_native_unit_of_measurement = UnitOfTime.SECONDS

    @property
    def native_value(self):
        """Return the state of the sensor."""
        return self._client_data.get("uptime")

class OmadaClientTrafficSensor(OmadaClientSensor):
    """Sensor for client traffic."""

    def __init__(self, coordinator, client_data, sensor_type, attribute):
        """Initialize the sensor."""
        super().__init__(coordinator, client_data, sensor_type)
        self._attribute = attribute

        # Only add unit for traffic_up and traffic_down
        if "traffic" in sensor_type:
            self._attr_native_unit_of_measurement = "MB"

    @property
    def native_value(self):
        """Return the state of the sensor."""
        value = self._client_data.get(self._attribute)
        if value is not None and "traffic" in self._sensor_type:
            # Convert bytes to megabytes
            return round(value / (1024 * 1024), 2)
        return value

class OmadaClientSignalSensor(OmadaClientSensor):
    """Sensor for client signal information."""

    def __init__(self, coordinator, client_data, sensor_type, attribute):
        """Initialize the sensor."""
        super().__init__(coordinator, client_data, sensor_type)
        self._attribute = attribute

        if sensor_type == "rssi":
            self._attr_native_unit_of_measurement = "dBm"
        elif "rate" in sensor_type:
            self._attr_native_unit_of_measurement = "Kbit/s"

    @property
    def native_value(self):
        """Return the state of the sensor."""
        return self._client_data.get(self._attribute)

class OmadaClientWifiModeSensor(OmadaClientSensor):
    """Sensor for WiFi mode information."""

    WIFI_MODE_MAP = {
        0: "11a",
        1: "11b",
        2: "11g",
        3: "11na",
        4: "11ng",
        5: "11ac",
        6: "11axa",
        7: "11axg",
        8: "11beg",
        9: "11bea"
    }

    def __init__(self, coordinator, client_data, sensor_type, attribute):
        """Initialize the sensor."""
        super().__init__(coordinator, client_data, sensor_type)
        self._attribute = attribute

    @property
    def native_value(self):
        """Return the state of the sensor."""
        mode = self._client_data.get(self._attribute)
        if mode is not None:
            try:
                return self.WIFI_MODE_MAP.get(int(mode), f"Unknown ({mode})")
            except (ValueError, TypeError):
                return f"Unknown ({mode})"
        return None

class OmadaClientRadioSensor(OmadaClientSensor):
    """Sensor for Radio Type information."""

    RADIO_TYPE_MAP = {
        0: "2.4 GHz",
        1: "5 GHz(1)",
        2: "5 GHz(2)",
        3: "6 GHz"
    }

    def __init__(self, coordinator, client_data, sensor_type, attribute):
        """Initialize the sensor."""
        super().__init__(coordinator, client_data, sensor_type)
        self._attribute = attribute

    @property
    def native_value(self):
        """Return the state of the sensor."""
        radio_id = self._client_data.get(self._attribute)
        if radio_id is not None:
            try:
                return self.RADIO_TYPE_MAP.get(int(radio_id), f"Unknown ({radio_id})")
            except (ValueError, TypeError):
                return f"Unknown ({radio_id})"
        return None

def create_client_sensors(coordinator, client):
    """Create sensors for a client based on available data."""
    sensors = []

    # Map of sensor definitions: (sensor_class, name, attribute)
    sensor_definitions = [
        (OmadaClientBasicSensor, "name", "name"),
        (OmadaClientBasicSensor, "gateway_name", "gatewayName"),
        (OmadaClientBasicSensor, "ip_address", "ip"),
        (OmadaClientBasicSensor, "mac_address", "mac"),
        (OmadaClientBasicSensor, "wireless", "wireless"),
        (OmadaClientBasicSensor, "network_name", "networkName"),
        (OmadaClientBasicSensor, "ssid", "ssid"),
        (OmadaClientSignalSensor, "signal_level", "signalLevel"),
        (OmadaClientBasicSensor, "signal_rank", "signalRank"),
        (OmadaClientWifiModeSensor, "wifi_mode", "wifiMode"),
        (OmadaClientBasicSensor, "ap_name", "apName"),
        (OmadaClientBasicSensor, "ap_mac", "apMac"),
        (OmadaClientRadioSensor, "radio_type", "radioId"),
        (OmadaClientBasicSensor, "channel", "channel"),
        (OmadaClientSignalSensor, "rx_rate", "rxRate"),
        (OmadaClientSignalSensor, "tx_rate", "txRate"),
        (OmadaClientSignalSensor, "rssi", "rssi"),
        (OmadaClientUptimeSensor, "uptime", None),
        (OmadaClientTrafficSensor, "traffic_up", "trafficUp"),
        (OmadaClientTrafficSensor, "traffic_down", "trafficDown"),
        (OmadaClientTrafficSensor, "packets_down", "downPacket"),
        (OmadaClientTrafficSensor, "packets_up", "upPacket"),
        (OmadaClientBasicSensor, "active", "active"),
    ]

    for sensor_class, name, attribute in sensor_definitions:
        # Skip if the attribute doesn't exist in client data
        if attribute is not None and attribute not in client:
            continue

        # Special handling for UptimeSensor which doesn't need an attribute
        if sensor_class == OmadaClientUptimeSensor:
            if "uptime" in client:
                sensors.append(sensor_class(coordinator, client))
        else:
            sensors.append(sensor_class(coordinator, client, name, attribute))

    return sensors


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> bool:
    """Set up sensors from a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities = []

    # Create sensors for ACL rules
    for device_type, rules in coordinator.data.get("acl_rules", {}).items():
        for rule in rules:
            entities.extend([
                OmadaTypeSensor(coordinator, rule, device_type, "acl"),
                OmadaIndexSensor(coordinator, rule, device_type, "acl"),
                OmadaProtocolSensor(coordinator, rule, device_type, "acl"),
                OmadaPolicySensor(coordinator, rule, device_type, "acl"),
            ])

    # Create sensors for URL filters
    for filter_type, filters in coordinator.data.get("url_filters", {}).items():
        for filter_rule in filters:
            entities.extend([
                OmadaTypeSensor(coordinator, filter_rule, filter_type, "url_filter"),
                OmadaIndexSensor(coordinator, filter_rule, filter_type, "url_filter"),
                OmadaPolicySensor(coordinator, filter_rule, filter_type, "url_filter"),
            ])

    # Create sensors for devices
    if coordinator.data.get("devices", {}).get("data"):
        for device in coordinator.data["devices"]["data"]:
            # Basic information sensors
            entities.extend([
                OmadaDeviceBasicSensor(coordinator, device, "type", "type"),
                OmadaDeviceBasicSensor(coordinator, device, "name", "name"),
                OmadaDeviceBasicSensor(coordinator, device, "mac_address", "mac"),
                OmadaDeviceBasicSensor(coordinator, device, "model", "model"),
                OmadaDeviceBasicSensor(coordinator, device, "model_display", "showModel"),
                OmadaDeviceBasicSensor(coordinator, device, "model_version", "modelVersion"),
                OmadaDeviceBasicSensor(coordinator, device, "firmware_version", "firmwareVersion"),
                OmadaDeviceBasicSensor(coordinator, device, "version", "version"),
                OmadaDeviceBasicSensor(coordinator, device, "hardware_version", "hwVersion"),
                OmadaDeviceBasicSensor(coordinator, device, "ip_address", "ip"),
                OmadaDeviceBasicSensor(coordinator, device, "public_ip", "publicIp"),
                OmadaDeviceUptimeSensor(coordinator, device)
            ])

    # Create sensors for clients
    if coordinator.data.get("clients", {}).get("data"):
        for client in coordinator.data["clients"]["data"]:
            entities.extend(create_client_sensors(coordinator, client))

    async_add_entities(entities)
    return True