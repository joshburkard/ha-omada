"""Constants for the Test HA Omada integration."""
from datetime import timedelta

DOMAIN = "omada"

CONF_URL = "url"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_SITE_NAME = "site_name"
CONF_SKIP_CERT_VERIFY = "skip_cert_verify"

DEFAULT_SCAN_INTERVAL = timedelta(seconds=30)
