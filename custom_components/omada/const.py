"""Constants for the Omada Controller integration."""
from datetime import timedelta

DOMAIN = "omada"
DEFAULT_UPDATE_INTERVAL = timedelta(seconds=30)

CONF_SITE_NAME = "site_name"
CONF_SKIP_CERT_VERIFY = "skip_cert_verify"

# Device types
DEVICE_TYPE_GATEWAY = 0
DEVICE_TYPE_SWITCH = 1
DEVICE_TYPE_EAP = 2

DEVICE_TYPE_NAMES = {
    DEVICE_TYPE_GATEWAY: "Gateway",
    DEVICE_TYPE_SWITCH: "Switch",
    DEVICE_TYPE_EAP: "EAP"
}