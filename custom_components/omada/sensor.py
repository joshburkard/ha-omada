"""Sensor platform for Omada Controller."""
from homeassistant.components.sensor import SensorEntity, SensorDeviceClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.const import UnitOfTime
from .const import DOMAIN, DEVICE_TYPE_NAMES

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
                if (rule.get("id") == self._device_data.get("id") or
                        ("name" in rule and "name" in self._device_data and rule["name"] == self._device_data["name"])):
                    return rule
        elif self._rule_type == "url_filter":
            for rule in self.coordinator.data["url_filters"].get(self._device_type, []):
                if (rule.get("id") == self._device_data.get("id") or
                        ("name" in rule and "name" in self._device_data and rule["name"] == self._device_data["name"])):
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

class OmadaACLRuleSensor(OmadaBaseSensor):
    """Sensor for ACL rule information."""

    # Type mapping for source and destination
    TYPE_MAP = {
        0: "Network",
        1: "IP Group",
        2: "IP-Port Group",
        4: "SSID",
        6: "IPv6 Group",
        7: "IPv6-Port Group"
    }

    # Protocol mapping
    PROTOCOL_MAP = {
        1: "ICMP",
        2: "IGMP",
        3: "GGP",
        4: "IP/IPENCAP",
        5: "ST",
        6: "TCP",
        7: "CBT",
        8: "EGP",
        9: "IGP",
        10: "BBN-RCC-MON",
        11: "NVP-II",
        12: "PUP",
        13: "ARGUS",
        14: "EMCON",
        15: "XNET",
        16: "CHAOS",
        17: "UDP",
        18: "MUX",
        19: "DCN-MEAS",
        20: "HMP",
        21: "PRM",
        22: "XNS-IDP",
        23: "TRUNK-1",
        24: "TRUNK-2",
        25: "LEAF-1",
        26: "LEAF-2",
        27: "RDP",
        28: "IRTP",
        29: "ISO-TP4",
        30: "NETBLT",
        31: "MFE-NSP",
        32: "MERIT-INP",
        33: "DCCP",
        34: "3PC",
        35: "IDPR",
        36: "XTP",
        37: "DDP",
        38: "IDPR-CMTP",
        39: "TP++",
        40: "IL",
        41: "IPv6",
        42: "SDRP",
        43: "IPv6-Route",
        44: "IPv6-Frag",
        45: "IDRP",
        46: "RSVP",
        47: "GRE",
        48: "DSR",
        49: "BNA",
        50: "ESP",
        51: "AH",
        52: "I-NLSP",
        53: "SwIPe",
        54: "NARP",
        55: "MOBILE",
        56: "TLSP",
        57: "SKIP",
        58: "IPv6-ICMP",
        59: "IPv6-NoNxt",
        60: "IPv6-Opts",
        61: "Any Host Internal Protocol",
        62: "CFTP",
        63: "Any Local Network",
        64: "SAT-EXPAK",
        65: "KRYPTOLAN",
        66: "RVD",
        67: "IPPC",
        68: "Any Distributed File System",
        69: "SAT-MON",
        70: "VISA",
        71: "IPCU",
        72: "CPNX",
        73: "CPHB",
        74: "WSN",
        75: "PVP",
        76: "BR-SAT-MON",
        77: "SUN-ND",
        78: "WB-MON",
        79: "WB-EXPAK",
        80: "ISO-IP",
        81: "VMTP",
        82: "SECURE-VMTP",
        83: "VINES",
        84: "TTP/IPTM",
        85: "NSFNET-IGP",
        86: "DGP",
        87: "TCF",
        88: "EIGRP",
        89: "OSPF",
        90: "Sprite-RPC",
        91: "LARP",
        92: "MTP",
        93: "AX.25",
        94: "OS",
        95: "MICP",
        96: "SCC-SP",
        97: "ETHERIP",
        98: "ENCAP",
        99: "Any Private Encryption",
        100: "GMTP",
        101: "IFMP",
        102: "PNNI",
        103: "PIM",
        104: "ARIS",
        105: "SCPS",
        106: "QNX",
        107: "A/N",
        108: "IPComp",
        109: "SNP",
        110: "Compaq-Peer",
        111: "IPX-in-IP",
        112: "VRRP",
        113: "PGM",
        114: "Any 0-hop Protocol",
        115: "L2TP",
        116: "DDX",
        117: "IATP",
        118: "STP",
        119: "SRP",
        120: "UTI",
        121: "SMP",
        122: "SM",
        123: "PTP",
        124: "IS-IS over IPv4",
        125: "FIRE",
        126: "CRTP",
        127: "CRUDP",
        128: "SSCOPMCE",
        129: "IPLT",
        130: "SPS",
        131: "PIPE",
        132: "SCTP",
        133: "FC",
        134: "RSVP-E2E-IGNORE",
        135: "Mobility Header",
        136: "UDPLite",
        137: "MPLS-in-IP",
        138: "manet",
        139: "HIP",
        140: "Shim6",
        141: "WESP",
        142: "ROHC",
        143: "Ethernet",
        144: "AGGFRAG",
        145: "NSH",
        256: "ALL"
    }

    def __init__(self, coordinator, rule_data, device_type, attribute):
        """Initialize the ACL rule sensor."""
        super().__init__(coordinator, rule_data, device_type, "acl", attribute)
        self._attribute = attribute
        self._logger = logging.getLogger(__name__)

    def _get_protocol_name(self, protocol_number):
        """Get protocol name from number with logging."""
        try:
            protocol_number = int(protocol_number)
            protocol_name = self.PROTOCOL_MAP.get(protocol_number)  # Changed from self._protocol_map to self.PROTOCOL_MAP
            self._logger.debug(
                "Converting protocol %s to %s (found in map: %s)",
                protocol_number,
                protocol_name,
                protocol_name is not None
            )
            return protocol_name or f"Protocol {protocol_number}"
        except (ValueError, TypeError) as e:
            self._logger.warning("Error converting protocol number: %s", e)
            return f"Protocol {protocol_number}"

    @property
    def native_value(self):
        """Return the state of the sensor."""
        if not self._device_data:
            return None

        value = self._device_data.get(self._attribute)

        if self._attribute == "protocols":
            if isinstance(value, list):
                protocol_names = []
                for protocol in value:
                    try:
                        protocol_num = int(protocol)
                        protocol_names.append(self.PROTOCOL_MAP.get(protocol_num, f"Protocol {protocol_num}"))
                    except (ValueError, TypeError):
                        protocol_names.append(f"Unknown Protocol ({protocol})")
                return ", ".join(protocol_names)
            return str(value)
        elif self._attribute == "policy":
            policy_map = {0: "Deny", 1: "Permit"}
            try:
                value = int(value)
                return policy_map.get(value, f"Unknown ({value})")
            except (TypeError, ValueError):
                return f"Unknown ({value})"
        elif self._attribute in ["sourceType", "destinationType"]:
            try:
                value = int(value)
                return self.TYPE_MAP.get(value, f"Unknown Type ({value})")
            except (TypeError, ValueError):
                return f"Unknown Type ({value})"

        return value

    @property
    def extra_state_attributes(self):
        """Return additional state attributes."""
        attrs = {
            "rule_type": "ACL",
            "device_type": DEVICE_TYPE_NAMES.get(self._device_type, self._device_type)
        }

        # Add raw values for certain attributes
        if self._attribute in ["policy", "protocols"]:
            raw_value = self._device_data.get(self._attribute)
            attrs["raw_value"] = self._device_data.get(self._attribute)

            # Add debug information for protocols
            #if self._attribute == "protocols" and isinstance(raw_value, list):
            #    protocol_list = []
            #    for protocol in raw_value:
            #        try:
            #            protocol_num = int(protocol)
            #            protocol_name = self._protocol_map.get(protocol_num)
            #            protocol_list.append({
            #                "number": protocol_num,
            #                "name": protocol_name or f"Protocol {protocol_num}"
            #            })
            #        except (ValueError, TypeError):
            #            protocol_list.append({
            #                "number": protocol,
            #                "name": "Invalid Protocol"
            #            })
            #    attrs["protocol_details"] = protocol_list

        return attrs

class OmadaACLSourceDestSensor(OmadaBaseSensor):
    """Sensor for ACL rule source and destination information."""

    # Type mapping for group types
    GROUP_TYPE_MAP = {
        0: "IP Group",
        1: "IP Port Group",
        2: "MAC Group",  # Not used currently
        3: "IPv6 Group",
        4: "IPv6 Port Group",
        5: "Country Group",  # Not used currently
        7: "Domain Group"    # Not used currently
    }

    def __init__(self, coordinator, rule_data, device_type, attribute):
        """Initialize the source/destination sensor."""
        super().__init__(coordinator, rule_data, device_type, "acl", attribute)
        self._attribute = attribute
        _LOGGER.debug(
            "Initializing %s sensor for rule %s with data: %s",
            attribute,
            rule_data.get("name"),
            rule_data
        )

    def _get_network_info(self, network_ids):
            """Get network information from coordinator data."""
            _LOGGER.debug("Getting network info for IDs: %s", network_ids)
            _LOGGER.debug("Available networks: %s", self.coordinator.data.get("networks", {}).get("result", {}).get("data", []))

            if not self.coordinator.data.get("networks", {}).get("result", {}).get("data"):
                _LOGGER.warning("No networks data available in coordinator")
                return None

            network_info = []
            for network in self.coordinator.data["networks"]["result"]["data"]:
                if network.get("id") in network_ids:
                    _LOGGER.debug("Found matching network: %s", network)
                    network_info.append({
                        "name": network.get("name", "Unknown Network"),
                        "id": network.get("id")
                    })

            return network_info if network_info else None

    def _get_group_info(self, group_ids, expected_type):
        """Get group information from coordinator data."""
        _LOGGER.debug("Getting group info for IDs: %s (expected type: %s)", group_ids, expected_type)
        _LOGGER.debug("Available groups: %s", self.coordinator.data.get("ip_groups", {}).get("result", {}).get("data", []))

        if not self.coordinator.data.get("ip_groups", {}).get("result", {}).get("data"):
            _LOGGER.warning("No groups data available in coordinator")
            return None

        group_info = []
        for group in self.coordinator.data["ip_groups"]["result"]["data"]:
            if group.get("groupId") in group_ids and group.get("type") == expected_type:
                _LOGGER.debug("Found matching group: %s", group)

                # Handle different group types
                if expected_type == 0:  # IP Group
                    addresses = []
                    for ip_entry in group.get("ipList", []):
                        ip = ip_entry.get("ip", "")
                        mask = ip_entry.get("mask", "")
                        description = ip_entry.get("description", "")
                        if ip and mask:
                            addr = f"{ip}/{mask}"
                            if description:
                                addr += f" ({description})"
                            addresses.append(addr)
                        elif ip:
                            addresses.append(ip)

                elif expected_type == 1:  # IP Port Group
                    addresses = []
                    for ip_entry in group.get("ipList", []):
                        ip = ip_entry.get("ip", "")
                        mask = ip_entry.get("mask", "")
                        if ip and mask:
                            addresses.append(f"{ip}/{mask}")
                        elif ip:
                            addresses.append(ip)
                    ports = group.get("portList", [])
                    port_masks = group.get("portMaskList", [])

                elif expected_type == 3:  # IPv6 Group
                    addresses = []
                    for ipv6_entry in group.get("ipv6List", []):
                        ip = ipv6_entry.get("ip", "")
                        prefix = ipv6_entry.get("prefix", "")
                        if ip and prefix:
                            addresses.append(f"{ip}/{prefix}")
                        elif ip:
                            addresses.append(ip)

                elif expected_type == 4:  # IPv6 Port Group
                    addresses = []
                    for ipv6_entry in group.get("ipv6List", []):
                        ip = ipv6_entry.get("ip", "")
                        prefix = ipv6_entry.get("prefix", "")
                        if ip and prefix:
                            addresses.append(f"{ip}/{prefix}")
                        elif ip:
                            addresses.append(ip)
                    ports = group.get("portList", [])
                    port_masks = group.get("portMaskList", [])

                group_data = {
                    "name": group.get("name", "Unknown Group"),
                    "type": self.GROUP_TYPE_MAP.get(expected_type, f"Unknown Type ({expected_type})"),
                    "addresses": addresses,
                }

                # Add ports if it's a port group
                if expected_type in [1, 4]:  # IP Port Group or IPv6 Port Group
                    group_data["ports"] = ports
                    group_data["port_masks"] = port_masks

                group_info.append(group_data)

        return group_info if group_info else None

    def _get_source_dest_value(self, type_value, ids_list):
        """Get the appropriate source/destination value based on type."""
        try:
            type_value = int(type_value)
            _LOGGER.debug(
                "Getting value for type %s with IDs: %s",
                type_value,
                ids_list
            )

            if type_value == 0:  # Network
                networks_info = self._get_network_info(ids_list)
                if networks_info:
                    return " | ".join([
                        f"{network['name']}"
                        for network in networks_info
                    ])
                return f"Unknown Network(s) ({', '.join(ids_list)})"

            elif type_value == 1:  # IP Group
                groups_info = self._get_group_info(ids_list, 0)
                if groups_info:
                    return " | ".join([
                        f"{group['name']} ({', '.join(group['addresses'])})"
                        for group in groups_info
                    ])
                return f"Unknown IP Group(s) ({', '.join(ids_list)})"

            elif type_value == 2:  # IP-Port Group
                groups_info = self._get_group_info(ids_list, 1)
                if groups_info:
                    return " | ".join([
                        f"{group['name']} ({', '.join(group['addresses'])}) Ports: {', '.join(group['ports'])}"
                        for group in groups_info
                    ])
                return f"Unknown IP-Port Group(s) ({', '.join(ids_list)})"

            elif type_value == 6:  # IPv6 Group
                groups_info = self._get_group_info(ids_list, 3)
                if groups_info:
                    return " | ".join([
                        f"{group['name']} ({', '.join(group['addresses'])})"
                        for group in groups_info
                    ])
                return f"Unknown IPv6 Group(s) ({', '.join(ids_list)})"

            elif type_value == 7:  # IPv6-Port Group
                groups_info = self._get_group_info(ids_list, 4)
                if groups_info:
                    return " | ".join([
                        f"{group['name']} ({', '.join(group['addresses'])}) Ports: {', '.join(group['ports'])}"
                        for group in groups_info
                    ])
                return f"Unknown IPv6-Port Group(s) ({', '.join(ids_list)})"

            else:
                return f"Unknown Type {type_value} ({', '.join(ids_list)})"

        except Exception as e:
            _LOGGER.error("Error processing type %s: %s", type_value, str(e))
            return f"Error: {str(e)}"

    @property
    def native_value(self):
        """Return the state of the sensor."""
        if not self._device_data:
            return None

        _LOGGER.info(
            "Getting native value for %s with data: %s",
            self._attribute,
            self._device_data
        )

        try:
            if self._attribute == "source":
                type_value = self._device_data.get("sourceType")
                ids_list = self._device_data.get("sourceIds", [])
                return self._get_source_dest_value(type_value, ids_list)
            elif self._attribute == "destination":
                type_value = self._device_data.get("destinationType")
                ids_list = self._device_data.get("destinationIds", [])
                return self._get_source_dest_value(type_value, ids_list)
        except Exception as e:
            _LOGGER.error(
                "Error getting value for %s: %s",
                self._attribute,
                str(e)
            )
            return f"Error: {str(e)}"

        return None

    @property
    def extra_state_attributes(self):
        """Return additional state attributes."""
        attrs = {
            "rule_type": "ACL",
            "device_type": DEVICE_TYPE_NAMES.get(self._device_type, self._device_type)
        }

        if self._attribute == "source":
            type_value = self._device_data.get("sourceType")
            ids_list = self._device_data.get("sourceIds", [])
            attrs.update({
                "source_type": type_value,
                "source_ids": ids_list,
            })

            # Add type-specific details
            if type_value == 0:  # Network
                networks_info = self._get_network_info(ids_list)
                if networks_info:
                    attrs["networks"] = networks_info
            elif type_value == 1:  # IP Group
                groups_info = self._get_group_info(ids_list, 0)
                if groups_info:
                    attrs["ip_groups"] = groups_info
            elif type_value == 2:  # IP-Port Group
                groups_info = self._get_group_info(ids_list, 1)
                if groups_info:
                    attrs["ip_port_groups"] = groups_info
            elif type_value == 6:  # IPv6 Group
                groups_info = self._get_group_info(ids_list, 3)
                if groups_info:
                    attrs["ipv6_groups"] = groups_info
            elif type_value == 7:  # IPv6-Port Group
                groups_info = self._get_group_info(ids_list, 4)
                if groups_info:
                    attrs["ipv6_port_groups"] = groups_info

        # Similar structure for destination
        elif self._attribute == "destination":
            # ... same structure as source, just with destination attributes
            type_value = self._device_data.get("destinationType")
            ids_list = self._device_data.get("destinationIds", [])
            attrs.update({
                "destination_type": type_value,
                "destination_ids": ids_list,
            })

            if type_value == 0:  # Network
                networks_info = self._get_network_info(ids_list)
                if networks_info:
                    attrs["networks"] = networks_info
            elif type_value == 1:  # IP Group
                groups_info = self._get_group_info(ids_list, 0)
                if groups_info:
                    attrs["ip_groups"] = groups_info
            elif type_value == 2:  # IP-Port Group
                groups_info = self._get_group_info(ids_list, 1)
                if groups_info:
                    attrs["ip_port_groups"] = groups_info
            elif type_value == 6:  # IPv6 Group
                groups_info = self._get_group_info(ids_list, 3)
                if groups_info:
                    attrs["ipv6_groups"] = groups_info
            elif type_value == 7:  # IPv6-Port Group
                groups_info = self._get_group_info(ids_list, 4)
                if groups_info:
                    attrs["ipv6_port_groups"] = groups_info

        return attrs

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


class OmadaURLFilterSensor(OmadaBaseSensor):
    """Sensor for URL filter information."""

    def __init__(self, coordinator, filter_data, filter_type, attribute):
        """Initialize the URL filter sensor."""
        super().__init__(coordinator, filter_data, filter_type, "url_filter", attribute)
        self._attribute = attribute

    @property
    def native_value(self):
        """Return the state of the sensor."""
        if not self._device_data:
            return None

        value = self._device_data.get(self._attribute)
        if self._attribute == "status":
            return "Enabled" if value else "Disabled"
        elif self._attribute == "mode":
            mode_map = {0: "Block Listed", 1: "Allow Listed"}
            return mode_map.get(value, f"Unknown ({value})")
        return value

    @property
    def extra_state_attributes(self):
        """Return additional state attributes."""
        attrs = {
            "rule_type": "URL Filter",
            "filter_type": self._device_type
        }

        # Add URLs if they exist
        if "urls" in self._device_data:
            attrs["urls"] = self._device_data["urls"]

        return attrs

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

def create_device_sensors(coordinator, device):
    """Create sensors for a device based on available data."""
    sensors = []
    sensor_definitions = [
        (OmadaDeviceBasicSensor, "name", "name"),
        (OmadaDeviceBasicSensor, "ip_address", "ip"),
        (OmadaDeviceBasicSensor, "mac_address", "mac"),
        (OmadaDeviceUptimeSensor, "uptime", None),
        # Add more device sensors as needed
    ]
    for sensor_class, name, attribute in sensor_definitions:
        if attribute is not None and attribute not in device:
            continue
        if sensor_class == OmadaDeviceUptimeSensor:
            if "uptime" in device:
                sensors.append(sensor_class(coordinator, device))
        else:
            sensors.append(sensor_class(coordinator, device, name, attribute))
    return sensors


def create_acl_rule_sensors(coordinator, rule, device_type):
    """Create sensors for an ACL rule based on available data."""
    sensors = []

    # Define available sensors and their corresponding attributes
    sensor_definitions = [
        (OmadaACLRuleSensor, "name", "name"),
        (OmadaACLRuleSensor, "policy", "policy"),
        (OmadaACLRuleSensor, "protocols", "protocols"),
        (OmadaACLRuleSensor, "src_ip", "srcIp"),
        (OmadaACLRuleSensor, "dst_ip", "dstIp"),
        (OmadaACLRuleSensor, "src_port", "srcPort"),
        (OmadaACLRuleSensor, "dst_port", "dstPort"),
        (OmadaACLRuleSensor, "status", "status"),
        (OmadaACLRuleSensor, "Source Type", "sourceType"),
        (OmadaACLRuleSensor, "Destination Type", "destinationType")
    ]

    # First add the basic sensors
    for sensor_class, name, attribute in sensor_definitions:
        if attribute in rule:
            sensor = sensor_class(coordinator, rule, device_type, attribute)
            _LOGGER.debug("Creating sensor %s for attribute %s", name, attribute)
            sensors.append(sensor)

    # Then separately handle source/destination sensors
    if "sourceType" in rule and "sourceIds" in rule:
        _LOGGER.debug("Creating source sensor for rule %s", rule.get("name"))
        sensors.append(OmadaACLSourceDestSensor(coordinator, rule, device_type, "source"))

    if "destinationType" in rule and "destinationIds" in rule:
        _LOGGER.debug("Creating destination sensor for rule %s", rule.get("name"))
        sensors.append(OmadaACLSourceDestSensor(coordinator, rule, device_type, "destination"))

    _LOGGER.debug("Created total %d sensors for rule %s", len(sensors), rule.get("name"))
    return sensors

def create_url_filter_sensors(coordinator, filter_rule, filter_type):
    """Create sensors for a URL filter based on available data."""
    sensors = []

    # Define available sensors and their corresponding attributes
    sensor_definitions = [
        (OmadaURLFilterSensor, "name", "name"),
        (OmadaURLFilterSensor, "status", "status"),
        (OmadaURLFilterSensor, "mode", "mode"),
        (OmadaURLFilterSensor, "description", "description")
    ]

    for sensor_class, name, attribute in sensor_definitions:
        if attribute in filter_rule:
            sensors.append(sensor_class(coordinator, filter_rule, filter_type, attribute))

    return sensors

async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> bool:
    """Set up sensors from a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities = []

    @callback
    def update_entities():
        """Update entities with new clients, devices, URL filters, and ACL rules."""
        new_entities = []

        # Add debug logging
        _LOGGER.debug("Coordinator data: %s", coordinator.data)

        # Create sensors for clients
        for client in coordinator.data.get("clients", {}).get("data", []):
            new_entities.extend(create_client_sensors(coordinator, client))

        # Create sensors for devices
        for device in coordinator.data.get("devices", {}).get("data", []):
            new_entities.extend(create_device_sensors(coordinator, device))

        # Create sensors for ACL rules
        for device_type, rules in coordinator.data.get("acl_rules", {}).items():
            _LOGGER.debug("Processing ACL rules for device type %s: %s", device_type, rules)
            for rule in rules:
                created_sensors = create_acl_rule_sensors(coordinator, rule, device_type)
                _LOGGER.debug("Created sensors for rule %s: %s", rule.get("name"), created_sensors)
                new_entities.extend(created_sensors)

        # Create sensors for URL filters
        for filter_type, filters in coordinator.data.get("url_filters", {}).items():
            for filter_rule in filters:
                new_entities.extend(create_url_filter_sensors(coordinator, filter_rule, filter_type))

        if new_entities:
            _LOGGER.debug("Adding new entities: %s", new_entities)
            async_add_entities(new_entities)
        else:
            _LOGGER.warning("No new entities found to add")

    coordinator.async_add_listener(update_entities)
    update_entities()
    return True
