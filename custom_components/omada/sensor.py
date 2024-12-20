"""Sensor platform for Test HA Omada."""
from datetime import datetime
import logging
from zoneinfo import ZoneInfo

from homeassistant.components.sensor import (
    SensorEntity,
    SensorStateClass,
    SensorDeviceClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.entity_registry import (
    async_get as er_async_get,
    RegistryEntryDisabler
)
from homeassistant.const import (
    UnitOfDataRate,
    UnitOfTime,
    UnitOfInformation,
    PERCENTAGE,
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
)
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .helpers import OmadaCoordinatorEntity, standardize_mac, is_valid_value

_LOGGER = logging.getLogger(__name__)

# ACL Rule sensor definitions
ACL_RULE_SENSOR_DEFINITIONS = [
    ("OmadaACLRuleSensor", "policy", "policy", "Policy"),
    ("OmadaACLRuleSensor", "protocols", "protocols", "Protocols"),
    ("OmadaACLRuleSensor", "src_ip", "srcIp", "Source IP"),
    ("OmadaACLRuleSensor", "dst_ip", "dstIp", "Destination IP"),
    ("OmadaACLRuleSensor", "src_port", "srcPort", "Source Port"),
    ("OmadaACLRuleSensor", "dst_port", "dstPort", "Destination Port"),
    ("OmadaACLRuleSensor", "status", "status", "Status"),
    ("OmadaACLRuleSensor", "source_type", "sourceType", "Source Type"),
    ("OmadaACLRuleSensor", "destination_type", "destinationType", "Destination Type"),
    ("OmadaACLRuleSensor", "source_ids", "sourceIds", "Source"),
    ("OmadaACLRuleSensor", "destination_ids", "destinationIds", "Destination")
]

# ACL Type mappings
TRAFFIC_TYPE_MAP = {
    0: "Network",
    1: "IP Group",
    2: "IP-Port Group",
    4: "SSID",
    6: "IPv6 Group",
    7: "IPv6-Port Group"
}

# Client sensor definitions tuple (class_name, entity_id, attribute, display_name)
# Update CLIENT_SENSOR_DEFINITIONS in sensor.py
CLIENT_SENSOR_DEFINITIONS = [
    ("OmadaClientBaseSensor", "active", "active", "Active"),
    ("OmadaClientBaseSensor", "channel", "channel", "Channel"),
    ("OmadaClientSignalSensor", "rssi", "rssi", "RSSI"),
    ("OmadaClientBaseSensor", "ssid", "ssid", "SSID"),
    ("OmadaClientTimeSensor", "uptime", "uptime", "Uptime"),
    ("OmadaClientBaseSensor", "wireless", "wireless", "Wireless"),
    ("OmadaClientBaseSensor", "gateway_name", "gatewayName", "Gateway Name"),
    ("OmadaClientBaseSensor", "ip_address", "ip", "IP Address"),
    ("OmadaClientBaseSensor", "mac_address", "mac", "MAC Address"),
    ("OmadaClientBaseSensor", "network_name", "networkName", "Network Name"),
    ("OmadaClientBaseSensor", "ap_name", "apName", "AP Name"),
    ("OmadaClientBaseSensor", "ap_mac", "apMac", "AP Mac"),
    ("OmadaClientSignalSensor", "signal_level", "signalLevel", "Signal Level"),
    ("OmadaClientSignalSensor", "signal_rank", "signalRank", "Signal Rank"),
    ("OmadaClientWifiSensor", "wifi_mode", "wifiMode", "WiFi Mode"),
    ("OmadaClientRadioSensor", "radio_id", "radioId", "Radio Type"),
    ("OmadaClientSpeedSensor", "rx_rate", "rxRate", "RX Rate"),
    ("OmadaClientSpeedSensor", "tx_rate", "txRate", "TX Rate"),
    ("OmadaClientTrafficSensor", "traffic_up", "trafficUp", "Traffic Up"),
    ("OmadaClientTrafficSensor", "traffic_down", "trafficDown", "Traffic Down"),
    ("OmadaClientPacketSensor", "down_packet", "downPacket", "Packets Down"),
    ("OmadaClientPacketSensor", "up_packet", "upPacket", "Packets Up")
]

# Define always-enabled sensors
ALWAYS_ENABLED_SENSORS = {
    "active", "channel", "rssi", "ssid", "uptime", "wireless",
    "gateway_name", "ip_address", "mac_address", "network_name",
    "ap_name", "ap_mac", "signal_level", "signal_rank", "wifi_mode",
    "radio_id", "rx_rate", "tx_rate"
}

# Device sensor definitions tuple (class_name, entity_id, attribute, display_name)
DEVICE_SENSOR_DEFINITIONS = [
    ("OmadaDeviceBasicSensor", "model", "model", "Model"),
    ("OmadaDeviceBasicSensor", "compound_model", "compoundModel", "Compound Model"),
    ("OmadaDeviceBasicSensor", "show_model", "showModel", "Show Model"),
    ("OmadaDeviceBasicSensor", "model_version", "modelVersion", "Model Version"),
    ("OmadaDeviceBasicSensor", "firmware_version", "firmwareVersion", "Firmware Version"),
    ("OmadaDeviceBasicSensor", "version", "version", "Version"),
    ("OmadaDeviceBasicSensor", "hw_version", "hwVersion", "Hardware Version"),
    ("OmadaDeviceBasicSensor", "ip", "ip", "IP Address"),
    ("OmadaDeviceBasicSensor", "public_ip", "publicIp", "Public IP"),
    ("OmadaDeviceTimeSensor", "uptime", "uptimeLong", "Uptime"),
    ("OmadaDeviceBasicSensor", "uptime_string", "uptime", "Uptime String"),
    ("OmadaDeviceBasicSensor", "status", "status", "Status"),
    ("OmadaDeviceBasicSensor", "adopt_fail_type", "adoptFailType", "Adopt Fail Type"),
    ("OmadaDeviceDateTimeSensor", "last_seen", "lastSeen", "Last Seen"),
    ("OmadaDeviceBasicSensor", "cpu_util", "cpuUtil", "CPU Utilization"),
    ("OmadaDeviceBasicSensor", "mem_util", "memUtil", "Memory Utilization"),
    ("OmadaDeviceTrafficSensor", "download", "download", "Download"),
    ("OmadaDeviceTrafficSensor", "upload", "upload", "Upload"),
    ("OmadaDeviceBasicSensor", "site", "site", "Site"),
    ("OmadaDeviceBasicSensor", "client_num", "clientNum", "Client Number"),
    ("OmadaDeviceBasicSensor", "serial_number", "sn", "Serial Number"),
    ("OmadaDeviceBasicSensor", "health_score", "healthScore", "Health Score"),
    ("OmadaDeviceBasicSensor", "category", "category", "Category"),
    ("OmadaDeviceBasicSensor", "config_sync_status", "configSyncStatus", "Config Sync Status"),
    ("OmadaDeviceBasicSensor", "support_running_config", "supportRunningConfig", "Support Running Config"),
    ("OmadaDeviceBasicSensor", "license_status", "licenseStatusStr", "License Status")
]

DEVICE_LICENSE_STATUS_MAP = {
    0: "unActive",
    1: "Unbind",
    2: "Expired",
    3: "Active"
}

# URL Filter source type mappings
URL_FILTER_SENSOR_DEFINITIONS = [
    ("OmadaURLFilterSensor", "policy", "policy", "Policy"),
    ("OmadaURLFilterSensor", "source_type", "sourceType", "Source Type"),
    ("OmadaURLFilterSensor", "source_ids", "sourceIds", "Source"),
    ("OmadaURLFilterSensor", "mode", "mode", "Mode"),
    ("OmadaURLFilterSensor", "urls", "urls", "URLs"),
    ("OmadaURLFilterSensor", "keywords", "keywords", "Keywords")
]

URL_FILTER_SOURCE_TYPE_MAP = {
    0: "Network",
    1: "IP Group",
    2: "SSID"
}

# Protocol mappings
PROTOCOL_MAP = {
    1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IP/IPENCAP", 5: "ST", 6: "TCP", 7: "CBT",
    8: "EGP", 9: "IGP", 10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP", 13: "ARGUS",
    14: "EMCON", 15: "XNET", 16: "CHAOS", 17: "UDP", 18: "MUX", 19: "DCN-MEAS",
    20: "HMP", 21: "PRM", 22: "XNS-IDP", 23: "TRUNK-1", 24: "TRUNK-2", 25: "LEAF-1",
    26: "LEAF-2", 27: "RDP", 28: "IRTP", 29: "ISO-TP4", 30: "NETBLT", 31: "MFE-NSP",
    32: "MERIT-INP", 33: "DCCP", 34: "3PC", 35: "IDPR", 36: "XTP", 37: "DDP",
    38: "IDPR-CMTP", 39: "TP++", 40: "IL", 41: "IPv6", 42: "SDRP", 43: "IPv6-Route",
    44: "IPv6-Frag", 45: "IDRP", 46: "RSVP", 47: "GRE", 48: "DSR", 49: "BNA",
    50: "ESP", 51: "AH", 52: "I-NLSP", 53: "SwIPe", 54: "NARP", 55: "MOBILE",
    56: "TLSP", 57: "SKIP", 58: "IPv6-ICMP", 59: "IPv6-NoNxt", 60: "IPv6-Opts",
    61: "Any Host Internal Protocol", 62: "CFTP", 63: "Any Local Network",
    64: "SAT-EXPAK", 65: "KRYPTOLAN", 66: "RVD", 67: "IPPC",
    68: "Any Distributed File System", 69: "SAT-MON", 70: "VISA", 71: "IPCU",
    72: "CPNX", 73: "CPHB", 74: "WSN", 75: "PVP", 76: "BR-SAT-MON", 77: "SUN-ND",
    78: "WB-MON", 79: "WB-EXPAK", 80: "ISO-IP", 81: "VMTP", 82: "SECURE-VMTP",
    83: "VINES", 84: "TTP/IPTM", 85: "NSFNET-IGP", 86: "DGP", 87: "TCF",
    88: "EIGRP", 89: "OSPF", 90: "Sprite-RPC", 91: "LARP", 92: "MTP", 93: "AX.25",
    94: "OS", 95: "MICP", 96: "SCC-SP", 97: "ETHERIP", 98: "ENCAP",
    99: "Any Private Encryption", 100: "GMTP", 101: "IFMP", 102: "PNNI", 103: "PIM",
    104: "ARIS", 105: "SCPS", 106: "QNX", 107: "A/N", 108: "IPComp", 109: "SNP",
    110: "Compaq-Peer", 111: "IPX-in-IP", 112: "VRRP", 113: "PGM",
    114: "Any 0-hop Protocol", 115: "L2TP", 116: "DDX", 117: "IATP", 118: "STP",
    119: "SRP", 120: "UTI", 121: "SMP", 122: "SM", 123: "PTP",
    124: "IS-IS over IPv4", 125: "FIRE", 126: "CRTP", 127: "CRUDP", 128: "SSCOPMCE",
    129: "IPLT", 130: "SPS", 131: "PIPE", 132: "SCTP", 133: "FC",
    134: "RSVP-E2E-IGNORE", 135: "Mobility Header", 136: "UDPLite", 137: "MPLS-in-IP",
    138: "manet", 139: "HIP", 140: "Shim6", 141: "WESP", 142: "ROHC",
    143: "Ethernet", 144: "AGGFRAG", 145: "NSH", 256: "ALL"
}

URL_FILTER_MODE_MAP = {
    0: "URL",
    1: "Keyword"
}

POLICY_MAP = {
    0: "Deny",
    1: "Permit"
}

# Radio Type mappings
RADIO_TYPE_MAP = {
    0: "2.4 GHz",
    1: "5 GHz(1)",
    2: "5 GHz(2)",
    3: "6 GHz"
}

# WiFi Mode mappings
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

class OmadaACLRuleSensor(CoordinatorEntity, SensorEntity):
    """Sensor for ACL rule attributes."""

    def __init__(self, coordinator, rule, device_type, entity_id, attribute, display_name, device_name):
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._rule = rule
        self._device_type = device_type
        self._attribute = attribute
        self._display_name = display_name
        self._last_value = None

        # Create unique IDs and names
        rule_id = rule.get("id", "unknown")
        self._attr_unique_id = f"acl_rule_{device_type}_{rule_id}_{entity_id}"
        self._attr_name = f"{device_name} {display_name}"

        # Set up device info
        if device_type == 'gateway':
            model_name = 'Omada Gateway ACL Rule'
        elif device_type == 'switch':
            model_name = 'Omada Switch ACL Rule'
        else:
            model_name = 'Omada EAP ACL Rule'

        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"acl_rule_{device_type}_{rule_id}")},
            "name": device_name,
            "manufacturer": "TP-Link",
            "model": model_name,
        }

    def _get_source_dest_value(self, ids, type_value):
        """Get readable values for source/destination IDs based on type."""
        if not ids:
            return "None"

        names = []
        type_value = int(type_value) if type_value is not None else None

        if type_value == 0:  # Network
            networks = self.coordinator.data.get("networks", [])
            for id in ids:
                for network in networks:
                    if network.get("id") == id:
                        names.append(network.get("name", id))
                        break
                else:
                    names.append(f"Unknown Network ({id})")

        elif type_value in [1, 2]:  # IP Group or IP-Port Group
            ip_groups = self.coordinator.data.get("ip_groups", [])
            for id in ids:
                for group in ip_groups:
                    if group.get("groupId") == id:
                        names.append(group.get("name", id))
                        break
                else:
                    names.append(f"Unknown Group ({id})")

        elif type_value == 4:  # SSID
            ssids = self.coordinator.data.get("ssids", [])
            for id in ids:
                for ssid in ssids:
                    if ssid.get("id") == id:
                        names.append(ssid.get("name", id))
                        break
                else:
                    names.append(f"Unknown SSID ({id})")

        return ", ".join(names) if names else "Unknown"

    def _format_value(self, value):
        """Format the value based on attribute type."""
        if self._attribute == "protocols" and isinstance(value, list):
            # Convert protocol numbers to names
            protocol_names = [PROTOCOL_MAP.get(int(p), f"Unknown ({p})") for p in value]
            return ", ".join(protocol_names)
        elif self._attribute in ["sourceType", "destinationType"]:
            # Convert type number to name
            try:
                return TRAFFIC_TYPE_MAP.get(int(value), f"Unknown ({value})")
            except (ValueError, TypeError):
                return f"Unknown ({value})"
        elif self._attribute == "policy":
            # Convert policy number to name
            try:
                return POLICY_MAP.get(int(value), f"Unknown ({value})")
            except (ValueError, TypeError):
                return f"Unknown ({value})"
        elif self._attribute in ["sourceIds", "destinationIds"]:
            # Get the corresponding type value
            type_attr = "sourceType" if self._attribute == "sourceIds" else "destinationType"
            type_value = None
            rules = self.coordinator.data["acl_rules"].get(self._device_type, [])
            for rule in rules:
                if rule.get("id") == self._rule.get("id"):
                    type_value = rule.get(type_attr)
                    break
            return self._get_source_dest_value(value, type_value)
        return value

    @property
    def native_value(self):
        """Return the state of the sensor."""
        rules = self.coordinator.data["acl_rules"].get(self._device_type, [])
        for rule in rules:
            if rule.get("id") == self._rule.get("id"):
                value = rule.get(self._attribute)
                self._last_value = self._format_value(value)
                return self._last_value
        return self._last_value

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        if self._last_value is not None:
            return True

        rules = self.coordinator.data["acl_rules"].get(self._device_type, [])
        for rule in rules:
            if rule.get("id") == self._rule.get("id"):
                return rule.get(self._attribute) is not None

        return False

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        rules = self.coordinator.data["acl_rules"].get(self._device_type, [])
        for rule in rules:
            if rule.get("id") == self._rule.get("id"):
                self._last_value = rule.get(self._attribute)
                break
        super()._handle_coordinator_update()

class OmadaClientBaseSensor(CoordinatorEntity, SensorEntity):
    def __init__(self, coordinator, client, entity_id, attribute, display_name):
        super().__init__(coordinator)
        self._client = client
        self._attribute = attribute
        self._display_name = display_name
        self._mac = standardize_mac(client['mac'])
        self._last_value = None

        self._attr_unique_id = f"client_{self._mac}_{entity_id}"
        client_name = client.get('name', self._mac)
        self._attr_name = f"{client_name} {display_name}"

        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"client_{self._mac}")},
            "name": client_name,
            "manufacturer": client.get("manufacturer", "TP-Link"),
            "model": "Omada Client",
            "sw_version": client.get("os", "Unknown"),
            "connections": {("mac", self._mac)}
        }

    @property
    def native_value(self):
        """Return the state of the sensor."""
        for client in self.coordinator.data.get("clients", []):
            if standardize_mac(client["mac"]) == self._mac:
                value = client.get(self._attribute)
                if value is not None:
                    self._last_value = value
                return value or self._last_value
        return self._last_value

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return any(
            standardize_mac(client["mac"]) == self._mac
            for client in self.coordinator.data.get("clients", [])
        )

class OmadaClientSignalSensor(OmadaClientBaseSensor):
    """Sensor for signal-related attributes."""

    def __init__(self, coordinator, client, entity_id, attribute, display_name):
        """Initialize the sensor."""
        super().__init__(coordinator, client, entity_id, attribute, display_name)
        self._attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
        self._attr_native_unit_of_measurement = SIGNAL_STRENGTH_DECIBELS_MILLIWATT
        self._attr_state_class = SensorStateClass.MEASUREMENT

class OmadaClientSpeedSensor(OmadaClientBaseSensor):
    """Sensor for speed-related attributes."""

    def __init__(self, coordinator, client, entity_id, attribute, display_name):
        """Initialize the sensor."""
        super().__init__(coordinator, client, entity_id, attribute, display_name)
        self._attr_native_unit_of_measurement = UnitOfDataRate.MEGABITS_PER_SECOND
        self._attr_state_class = SensorStateClass.MEASUREMENT

class OmadaClientTrafficSensor(OmadaClientBaseSensor):
    """Sensor for traffic-related attributes."""

    def __init__(self, coordinator, client, entity_id, attribute, display_name):
        """Initialize the sensor."""
        super().__init__(coordinator, client, entity_id, attribute, display_name)
        self._attr_native_unit_of_measurement = UnitOfDataRate.BYTES_PER_SECOND
        self._attr_state_class = SensorStateClass.MEASUREMENT

class OmadaClientPacketSensor(OmadaClientBaseSensor):
    """Sensor for packet-related attributes."""

    def __init__(self, coordinator, client, entity_id, attribute, display_name):
        """Initialize the sensor."""
        super().__init__(coordinator, client, entity_id, attribute, display_name)
        self._attr_state_class = SensorStateClass.TOTAL

class OmadaClientTimeSensor(OmadaClientBaseSensor):
    """Sensor for time-related attributes."""

    def __init__(self, coordinator, client, entity_id, attribute, display_name):
        """Initialize the sensor."""
        super().__init__(coordinator, client, entity_id, attribute, display_name)
        self._attr_device_class = SensorDeviceClass.DURATION
        self._attr_native_unit_of_measurement = UnitOfTime.SECONDS
        self._attr_state_class = SensorStateClass.TOTAL

class OmadaClientWifiSensor(OmadaClientBaseSensor):
    """Sensor for WiFi mode."""

    @property
    def native_value(self):
        """Return the WiFi mode."""
        for client in self.coordinator.data.get("clients", []):
            if standardize_mac(client["mac"]) == self._mac:
                mode = client.get(self._attribute)
                return WIFI_MODE_MAP.get(mode, f"Unknown ({mode})")
        return None

class OmadaClientRadioSensor(OmadaClientBaseSensor):
    """Sensor for radio type."""

    def __init__(self, coordinator, client, entity_id, attribute, display_name):
        """Initialize the sensor."""
        super().__init__(coordinator, client, entity_id, attribute, display_name)
        # self._attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self):
        """Return the radio type."""
        for client in self.coordinator.data.get("clients", []):
            if standardize_mac(client["mac"]) == self._mac:
                radio_id = client.get(self._attribute)
                return RADIO_TYPE_MAP.get(radio_id, f"Unknown ({radio_id})")
        return None

class OmadaDeviceBasicSensor(CoordinatorEntity, SensorEntity):
    """Basic sensor for Omada device attributes."""

    def __init__(self, coordinator, device, entity_id, attribute, display_name):
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._device = device
        self._attribute = attribute
        self._display_name = display_name

        # Set unique_id as combination of MAC and sensor type
        self._attr_unique_id = f"device_{device['mac']}_{entity_id}"

        # Set name as combination of device name and sensor display name
        device_name = device.get('name', device['mac'])
        self._attr_name = f"{device_name} {display_name}"

        # Set up device info
        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"device_{device['mac']}")},
            "name": device_name,
            "manufacturer": "TP-Link",
            "model": device.get("model", "Omada Device"),
            "sw_version": device.get("firmwareVersion", "Unknown"),
        }

        # Set device class for specific attributes
        if attribute in ["cpuUtil", "memUtil"]:
            self._attr_native_unit_of_measurement = PERCENTAGE

    @property
    def state_class(self):
        """Return the state class."""
        if self._attribute in ["cpuUtil", "memUtil"]:
            return SensorStateClass.MEASUREMENT
        return None

    @property
    def native_value(self):
        """Return the state of the sensor."""
        for device in self.coordinator.data["devices"]:
            if device["mac"] == self._device["mac"]:
                return device.get(self._attribute)
        return None

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        device_found = any(
            device["mac"] == self._device["mac"]
            for device in self.coordinator.data["devices"]
        )
        return self.coordinator.last_update_success and device_found

class OmadaDeviceDateTimeSensor(OmadaDeviceBasicSensor):
    """Sensor for datetime-related device attributes."""

    @property
    def device_class(self):
        """Return the device class."""
        return SensorDeviceClass.TIMESTAMP

    @property
    def native_value(self):
        """Return the state of the sensor."""
        for device in self.coordinator.data["devices"]:
            if device["mac"] == self._device["mac"]:
                timestamp = device.get(self._attribute)
                if timestamp:
                    # Convert milliseconds to seconds and add timezone information
                    try:
                        naive_dt = datetime.fromtimestamp(timestamp / 1000)
                        return dt_util.as_local(naive_dt)
                    except Exception as e:
                        _LOGGER.error("Error converting timestamp %s: %s", timestamp, e)
                        return None
        return None

class OmadaDeviceTimeSensor(OmadaDeviceBasicSensor):
    """Sensor for time-related device attributes."""

    @property
    def device_class(self):
        """Return the device class."""
        return SensorDeviceClass.DURATION

    @property
    def native_unit_of_measurement(self):
        """Return the unit of measurement."""
        return UnitOfTime.SECONDS

    @property
    def state_class(self):
        """Return the state class."""
        return SensorStateClass.TOTAL

class OmadaDeviceTrafficSensor(OmadaDeviceBasicSensor):
    """Sensor for traffic-related device attributes."""

    @property
    def device_class(self):
        """Return the device class."""
        return SensorDeviceClass.DATA_SIZE

    @property
    def native_unit_of_measurement(self):
        """Return the unit of measurement."""
        return UnitOfInformation.BYTES

    @property
    def state_class(self):
        """Return the state class."""
        return SensorStateClass.TOTAL

async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the sensors."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]["coordinator"]
    entity_registry = er_async_get(hass)

    @callback
    def add_entities():
        """Add new entities."""
        new_entities = []
        tracked_entities = coordinator.tracked_entities["sensor"]

        # Add device sensors
        if "devices" in coordinator.data:
            for device in coordinator.data["devices"]:
                device_mac = device.get("mac")
                if not device_mac:
                    continue

                for class_name, entity_id, attribute, display_name in DEVICE_SENSOR_DEFINITIONS:
                    entity_key = f"device_{device_mac}_{entity_id}"
                    if entity_key in tracked_entities:
                        continue

                    value = device.get(attribute)
                    if not is_valid_value(value):
                        continue

                    sensor_class = globals()[class_name]
                    entity = sensor_class(coordinator, device, entity_id, attribute, display_name)
                    tracked_entities[entity_key] = entity
                    new_entities.append(entity)

        # Add client sensors
        # Only process active clients
        active_clients = [
            client for client in coordinator.data.get("clients", [])
            if client.get("active", False)
        ]

        for client in active_clients:
            mac = standardize_mac(client.get("mac", ""))
            if not mac:
                continue

            _LOGGER.debug("Processing active client for sensors: %s", mac)

            for class_name, entity_id, attribute, display_name in CLIENT_SENSOR_DEFINITIONS:
                entity_key = f"client_{mac}_{entity_id}"

                # Skip if already tracking
                if entity_key in tracked_entities:
                    continue

                # Create sensor if it has valid data
                value = client.get(attribute)
                if value is not None:
                    try:
                        sensor_class = globals()[class_name]
                        entity = sensor_class(coordinator, client, entity_id, attribute, display_name)
                        tracked_entities[entity_key] = entity
                        new_entities.append(entity)
                        _LOGGER.debug("Created sensor %s for client %s", entity_key, mac)
                    except Exception as e:
                        _LOGGER.error("Error creating sensor %s: %s", entity_key, str(e))

        # Add ACL rule sensors
        if "acl_rules" in coordinator.data:
            for device_type in ["gateway", "switch", "eap"]:
                if device_type not in coordinator.data["acl_rules"]:
                    continue

                for rule in coordinator.data["acl_rules"][device_type]:
                    rule_id = rule.get("id")
                    if not rule_id:
                        continue

                    rule_name = rule.get("name", rule.get("id", "Unknown"))
                    if device_type == 'gateway':
                        device_type_name = 'Gateway'
                        device_name = f"Omada Gateway ACL Rule - {rule_name}"
                    elif device_type == 'switch':
                        device_type_name = 'Switch'
                        device_name = f"Omada Switch ACL Rule - {rule_name}"
                    else:
                        device_type_name = 'EAP'
                        device_name = f"Omada EAP ACL Rule - {rule_name}"
                    # device_name = f"Omada ACL {device_type.capitalize()} Rule - {rule_name}"

                    for class_name, entity_id, attribute, display_name in ACL_RULE_SENSOR_DEFINITIONS:
                        entity_key = f"acl_rule_{device_type}_{rule_id}_{entity_id}"
                        if entity_key in tracked_entities:
                            continue

                        value = rule.get(attribute)
                        if not is_valid_value(value):
                            continue

                        sensor_class = globals()[class_name]
                        entity = sensor_class(
                            coordinator,
                            rule,
                            device_type,
                            entity_id,
                            attribute,
                            display_name,
                            device_name
                        )
                        tracked_entities[entity_key] = entity
                        new_entities.append(entity)

        # Add URL filter sensors
        if "url_filters" in coordinator.data:
            for filter_type in ["gateway", "ap"]:
                if filter_type not in coordinator.data["url_filters"]:
                    continue

                for rule in coordinator.data["url_filters"][filter_type]:
                    rule_id = rule.get("id")
                    if not rule_id:
                        continue

                    rule_name = rule.get("name", rule.get("id", "Unknown"))
                    device_name = f"Omada {'Gateway' if filter_type == 'gateway' else 'EAP'} URL Filter - {rule_name}"

                    for class_name, entity_id, attribute, display_name in URL_FILTER_SENSOR_DEFINITIONS:
                        entity_key = f"url_filter_{filter_type}_{rule_id}_{entity_id}"
                        if entity_key in tracked_entities:
                            continue

                        value = rule.get(attribute)
                        if not is_valid_value(value):
                            continue

                        sensor_class = globals()[class_name]
                        entity = sensor_class(
                            coordinator,
                            rule,
                            filter_type,
                            entity_id,
                            attribute,
                            display_name,
                            device_name
                        )
                        tracked_entities[entity_key] = entity
                        new_entities.append(entity)

        if new_entities:
            async_add_entities(new_entities)

    coordinator.async_add_listener(add_entities)
    add_entities()

def add_client_sensors(coordinator, client):
    """Add sensors for a specific client."""
    new_entities = []
    mac = standardize_mac(client["mac"])

    for class_name, entity_id, attribute, display_name in CLIENT_SENSOR_DEFINITIONS:
        entity_key = f"client_{mac}_{entity_id}"

        # Skip if already exists
        if entity_key in coordinator.tracked_entities["sensor"]:
            continue

        # Check if sensor should be created
        value = client.get(attribute)
        if class_name in ["OmadaClientWifiSensor", "OmadaClientRadioSensor"]:
            if not value:
                continue
        elif class_name in ["OmadaClientSignalSensor", "OmadaClientSpeedSensor", "OmadaClientTrafficSensor"]:
            if not value or (isinstance(value, (int, float)) and value == 0):
                continue
        elif not is_valid_value(value):
            continue

        try:
            sensor_class = globals()[class_name]
            entity = sensor_class(coordinator, client, entity_id, attribute, display_name)
            coordinator.tracked_entities["sensor"][entity_key] = entity
            new_entities.append(entity)
            _LOGGER.debug("Created sensor %s for client %s", entity_key, mac)
        except Exception as e:
            _LOGGER.error("Error creating sensor %s: %s", entity_key, str(e))

    if new_entities:
        coordinator.hass.async_add_job(coordinator.hass.config_entries.async_forward_entry_entities,
                                     coordinator.config_entry_id, new_entities, "sensor")


class OmadaURLFilterSensor(OmadaCoordinatorEntity, SensorEntity):
    """Sensor for URL filter attributes."""

    def __init__(self, coordinator, rule, filter_type, entity_id, attribute, display_name, device_name):
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._rule = rule
        self._filter_type = filter_type
        self._attribute = attribute
        self._display_name = display_name
        self._last_value = None

        rule_id = rule.get("id", "unknown")
        self._attr_unique_id = f"url_filter_{filter_type}_{rule_id}_{entity_id}"
        self._attr_name = f"{device_name} {display_name}"

        model_name = f"Omada {'Gateway' if filter_type == 'gateway' else 'EAP'} URL Filter"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"url_filter_{filter_type}_{rule_id}")},
            "name": device_name,
            "manufacturer": "TP-Link",
            "model": model_name,
        }

    def _format_value(self, value):
        """Format the value based on attribute type."""
        if self._attribute == "mode":
            return URL_FILTER_MODE_MAP.get(value, f"Unknown ({value})")
        elif self._attribute == "sourceType":
            try:
                return URL_FILTER_SOURCE_TYPE_MAP.get(int(value), f"Unknown ({value})")
            except (ValueError, TypeError):
                return f"Unknown ({value})"
        elif self._attribute == "policy":
            try:
                return POLICY_MAP.get(int(value), f"Unknown ({value})")
            except (ValueError, TypeError):
                return f"Unknown ({value})"
        elif self._attribute == "sourceIds":
            type_value = self._rule.get("sourceType")
            return self._get_source_dest_value(value, type_value)
        elif self._attribute in ["urls", "keywords"]:
            if isinstance(value, list):
                return ", ".join(value)
            return str(value) if value else ""
        return value

    def _get_source_dest_value(self, ids, type_value):
        """Get readable values for source/destination IDs based on type."""
        if not ids:
            return "None"

        names = []
        type_value = int(type_value) if type_value is not None else None

        if type_value == 0:  # Network
            networks = self.coordinator.data.get("networks", [])
            for id in ids:
                for network in networks:
                    if network.get("id") == id:
                        names.append(network.get("name", id))
                        break
                else:
                    names.append(f"Unknown Network ({id})")

        elif type_value == 1:  # IP Group
            ip_groups = self.coordinator.data.get("ip_groups", [])
            for id in ids:
                for group in ip_groups:
                    if group.get("groupId") == id:
                        names.append(group.get("name", id))
                        break
                else:
                    names.append(f"Unknown Group ({id})")

        elif type_value == 2:  # SSID
            ssids = self.coordinator.data.get("ssids", [])
            for id in ids:
                for ssid in ssids:
                    if ssid.get("id") == id:
                        names.append(ssid.get("name", id))
                        break
                else:
                    names.append(f"Unknown SSID ({id})")

        return ", ".join(names) if names else "Unknown"

    @property
    def native_value(self):
        """Return the state of the sensor."""
        rules = self.coordinator.data["url_filters"].get(self._filter_type, [])
        for rule in rules:
            if rule.get("id") == self._rule.get("id"):
                value = rule.get(self._attribute)
                self._last_value = self._format_value(value)
                return self._last_value
        return self._last_value
