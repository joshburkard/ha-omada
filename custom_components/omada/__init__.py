"""The Omada Controller integration."""
import logging
from datetime import timedelta
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_URL,
    CONF_USERNAME,
    CONF_PASSWORD,
    Platform,
    CONF_SCAN_INTERVAL,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
    UpdateFailed,
)
from homeassistant.helpers.entity_registry import (
    async_get as er_async_get,
    async_entries_for_config_entry
)
from homeassistant.helpers import device_registry as dr

from .const import DOMAIN, CONF_SITE_NAME, CONF_SKIP_CERT_VERIFY, DEFAULT_UPDATE_INTERVAL

_LOGGER = logging.getLogger(__name__)
PLATFORMS = [Platform.SENSOR, Platform.SWITCH, Platform.DEVICE_TRACKER]

class OmadaAPI:
    """Class to handle Omada API calls."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        site_name: str,
        skip_cert_verify: bool = False
    ) -> None:
        """Initialize the API."""
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.username = username
        self.password = password
        self.site_name = site_name
        self.skip_cert_verify = skip_cert_verify
        self.omada_id = None
        self.token = None
        self.site_id = None
        self.session = requests.Session()

        if skip_cert_verify:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            self.session.verify = False

    def authenticate(self):
        """Authenticate with the Omada Controller."""
        try:
            # Get Omada ID
            _LOGGER.debug("Getting Omada ID from %s", f"{self.base_url}/api/info")
            response = self.session.get(
                f"{self.base_url}/api/info",
                verify=not self.skip_cert_verify
            )
            response.raise_for_status()
            info_data = response.json()
            _LOGGER.debug("Info response: %s", info_data)
            self.omada_id = info_data["result"].get("omadacId")

            if not self.omada_id:
                raise ValueError("Failed to get omadacId from /api/info")

            # Login
            login_data = {
                "username": self.username,
                "password": self.password
            }
            login_url = f"{self.base_url}/{self.omada_id}/api/v2/login"
            _LOGGER.debug("Logging in to %s", login_url)

            # Make sure we have the correct headers for login
            self.session.headers.update({
                "Content-Type": "application/json;charset=UTF-8",
                "Accept": "application/json, text/plain, */*"
            })

            response = self.session.post(
                login_url,
                json=login_data,
                verify=not self.skip_cert_verify
            )
            response.raise_for_status()
            login_result = response.json()
            _LOGGER.debug("Login response: %s", login_result)
            _LOGGER.debug("Login cookies: %s", dict(response.cookies))

            # Get the token from the response
            if "result" in login_result and isinstance(login_result["result"], dict):
                self.token = login_result["result"].get("token")
            else:
                self.token = login_result.get("token")

            # Get Csrf token from cookies if not in response
            if not self.token:
                csrf_cookie = self.session.cookies.get("CSRF-TOKEN")
                if csrf_cookie:
                    self.token = csrf_cookie
                else:
                    raise ValueError("No token found in response or cookies")

            _LOGGER.debug("Using token: %s", self.token)

            # Update session headers with the token
            self.session.headers.update({
                "Csrf-Token": self.token,
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*"
            })

            # Get Site ID
            sites_url = f"{self.base_url}/{self.omada_id}/api/v2/user/sites"
            _LOGGER.debug("Getting sites from %s", sites_url)
            _LOGGER.debug("Request headers: %s", dict(self.session.headers))
            _LOGGER.debug("Session cookies: %s", dict(self.session.cookies))

            response = self.session.get(
                sites_url,
                verify=not self.skip_cert_verify
            )
            response.raise_for_status()
            sites_data = response.json()
            _LOGGER.debug("Sites response: %s", sites_data)

            # Extract sites from the response
            sites = sites_data["result"]["data"]

            for site in sites:
                if site.get("name") == self.site_name:
                    self.site_id = site.get("id")
                    break

            if not self.site_id:
                raise ValueError(f"Site '{self.site_name}' not found")

            _LOGGER.info("Successfully authenticated with Omada Controller")
            return True

        except Exception as e:
            _LOGGER.error("Authentication failed: %s", str(e))
            return False

    def _make_request(self, method, url, **kwargs):
        """Make a request with proper error handling and session management."""
        try:
            response = self.session.request(method, url, verify=not self.skip_cert_verify, **kwargs)
            response.raise_for_status()
            data = response.json()

            if isinstance(data, dict) and "errorCode" in data and data["errorCode"] != 0:
                raise ValueError(f"API Error: {data['msg']} (Code: {data['errorCode']})")

            return data
        except Exception as e:
            _LOGGER.error("Request failed: %s %s - %s", method, url, str(e))
            raise

    def get_acl_rules(self, device_type):
        """Get ACL rules for a specific device type."""
        try:
            url = f"{self.base_url}/{self.omada_id}/api/v2/sites/{self.site_id}/setting/firewall/acls?type={device_type}"
            _LOGGER.debug("Getting ACL rules from %s", url)
            return self._make_request("GET", url)
        except Exception as e:
            _LOGGER.error("Failed to get ACL rules: %s", str(e))
            return []

    def get_url_filters(self, filter_type):
        """Get URL filters for a specific type."""
        try:
            url = f"{self.base_url}/{self.omada_id}/api/v2/sites/{self.site_id}/setting/firewall/urlfilterings?type={filter_type}"
            _LOGGER.debug("Getting URL filters from %s", url)
            return self._make_request("GET", url)
        except Exception as e:
            _LOGGER.error("Failed to get URL filters: %s", str(e))
            return []

    def update_acl_rule(self, rule_id: str, payload: dict) -> bool:
        """Update an ACL rule."""
        try:
            url = f"{self.base_url}/{self.omada_id}/api/v2/sites/{self.site_id}/setting/firewall/acls/{rule_id}"
            _LOGGER.debug("Updating ACL rule at %s with payload: %s", url, payload)

            response = self._make_request("PUT", url, json=payload)
            return response.get("errorCode", -1) == 0

        except Exception as e:
            _LOGGER.error("Failed to update ACL rule: %s", str(e))
            return False

    def update_url_filter(self, rule_id: str, payload: dict) -> bool:
        """Update a URL filter."""
        try:
            url = f"{self.base_url}/{self.omada_id}/api/v2/sites/{self.site_id}/setting/firewall/urlfilterings/{rule_id}"
            _LOGGER.debug("Updating URL filter at %s with payload: %s", url, payload)

            response = self._make_request("PUT", url, json=payload)
            return response.get("errorCode", -1) == 0

        except Exception as e:
            _LOGGER.error("Failed to update URL filter: %s", str(e))
            return False

    def get_devices(self):
        """Get all devices from Omada Controller."""
        try:
            url = f"{self.base_url}/{self.omada_id}/api/v2/sites/{self.site_id}/grid/devices"
            _LOGGER.debug("Getting devices from %s", url)
            return self._make_request("GET", url)
        except Exception as e:
            _LOGGER.error("Failed to get devices: %s", str(e))
            return []

    def get_clients(self):
        """Get all clients from Omada Controller."""
        try:
            all_clients = []
            current_page = 1
            page_size = 10
            total_rows = None

            while True:
                url = f"{self.base_url}/{self.omada_id}/api/v2/sites/{self.site_id}/clients?currentPage={current_page}&currentPageSize={page_size}&filters.active=true"
                _LOGGER.debug("Getting clients page %s from %s", current_page, url)

                response = self._make_request("GET", url)
                if not response or "result" not in response:
                    break

                # Get total number of rows if we don't have it yet
                if total_rows is None:
                    total_rows = response["result"].get("totalRows", 0)
                    _LOGGER.debug("Total clients to fetch: %s", total_rows)

                # Get current page's data
                page_data = response["result"].get("data", [])
                all_clients.extend(page_data)

                # Calculate if we need more pages
                clients_so_far = len(all_clients)
                _LOGGER.debug("Fetched %s clients so far out of %s", clients_so_far, total_rows)

                if clients_so_far >= total_rows or not page_data:
                    break

                current_page += 1

            _LOGGER.debug("Finished fetching all %s clients", len(all_clients))
            return {
                "errorCode": 0,
                "msg": "Success.",
                "result": {
                    "totalRows": len(all_clients),
                    "data": all_clients
                }
            }

        except Exception as e:
            _LOGGER.error("Failed to get clients: %s", str(e))
            return []

class OmadaDataUpdateCoordinator(DataUpdateCoordinator):
    """Class to manage fetching Omada data."""

    def __init__(self, hass: HomeAssistant, api: OmadaAPI, update_interval: timedelta):
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=update_interval,
        )
        self.api = api
        self._entity_registry = er_async_get(self.hass)
        self._device_registry = dr.async_get(self.hass)
        self._pending_removals = set()

    async def trigger_removal(self, entity_id: str, device_id: str):
        """Trigger removal of an entity and its associated device."""
        if entity_id in self._pending_removals:
            return

        self._pending_removals.add(entity_id)

        try:
            device = self._device_registry.async_get_device({(DOMAIN, device_id)})
            if device:
                # Get all entities for this device
                device_entities = [
                    entry.entity_id
                    for entry in self._entity_registry.entities.values()
                    if entry.device_id == device.id
                ]

                # Remove all entities for this device
                for ent_id in device_entities:
                    _LOGGER.debug("Removing entity %s for device %s", ent_id, device_id)
                    self._entity_registry.async_remove(ent_id)

                # Remove the device itself
                _LOGGER.debug("Removing device %s", device_id)
                self._device_registry.async_remove_device(device.id)

        except Exception as err:
            _LOGGER.error("Error removing device and entities: %s", str(err))
        finally:
            self._pending_removals.discard(entity_id)

    async def _check_missing_entities(self, data):
        """Check and remove entities that no longer exist in the data."""
        # Build sets of current valid device IDs
        current_acl_devices = set()
        current_url_filter_devices = set()
        devices_to_remove = []

        # Add ACL rule devices
        for device_type, rules in data["acl_rules"].items():
            for rule in rules:
                if "name" in rule:
                    device_id = f"omada_acl_{rule['name']}_{device_type}"
                    current_acl_devices.add(device_id)

        # Add URL filter devices
        for filter_type, filters in data["url_filters"].items():
            for filter_rule in filters:
                if "name" in filter_rule:
                    device_id = f"omada_url_filter_{filter_rule['name']}_{filter_type}"
                    current_url_filter_devices.add(device_id)

        # Create list of devices to check
        device_list = list(self._device_registry.devices.values())

        # Check all devices and create removal list
        for device in device_list:
            for identifier in device.identifiers:
                if identifier[0] == DOMAIN:
                    device_id = identifier[1]

                    # Check ACL devices
                    if device_id.startswith("omada_acl_") and device_id not in current_acl_devices:
                        _LOGGER.debug("ACL device %s no longer exists, marking for removal", device_id)
                        # Get any entity from this device for removal
                        device_entities = [
                            entry.entity_id
                            for entry in self._entity_registry.entities.values()
                            if entry.device_id == device.id
                        ]
                        if device_entities:
                            devices_to_remove.append((device_entities[0], device_id))

                    # Check URL filter devices
                    elif device_id.startswith("omada_url_filter_") and device_id not in current_url_filter_devices:
                        _LOGGER.debug("URL filter device %s no longer exists, marking for removal", device_id)
                        # Get any entity from this device for removal
                        device_entities = [
                            entry.entity_id
                            for entry in self._entity_registry.entities.values()
                            if entry.device_id == device.id
                        ]
                        if device_entities:
                            devices_to_remove.append((device_entities[0], device_id))

        # Process removals after iteration is complete
        for entity_id, device_id in devices_to_remove:
            await self.trigger_removal(entity_id, device_id)

    async def _async_update_data(self):
        """Fetch data from API."""
        try:
            data = {
                "acl_rules": {},
                "url_filters": {},
                "devices": {"data": []},
                "clients": {"data": []},
            }

            # Get ACL rules
            for device_type in [0, 1, 2]:  # Gateway, Switch, EAP
                _LOGGER.debug("Fetching ACL rules for device type %s", device_type)
                rules = await self.hass.async_add_executor_job(
                    self.api.get_acl_rules, device_type
                )
                if rules and "result" in rules and "data" in rules["result"]:
                    data["acl_rules"][device_type] = rules["result"]["data"]
                else:
                    data["acl_rules"][device_type] = []

            # Get URL filters
            for filter_type in ["gateway", "ap"]:
                _LOGGER.debug("Fetching URL filters for type %s", filter_type)
                filters = await self.hass.async_add_executor_job(
                    self.api.get_url_filters, filter_type
                )
                if filters and "result" in filters and "data" in filters["result"]:
                    data["url_filters"][filter_type] = filters["result"]["data"]
                else:
                    data["url_filters"][filter_type] = []

            # Get devices data
            devices = await self.hass.async_add_executor_job(
                self.api.get_devices
            )
            if devices and "result" in devices and "data" in devices["result"]:
                data["devices"] = {"data": devices["result"]["data"]}

            # Get clients data
            clients = await self.hass.async_add_executor_job(
                self.api.get_clients
            )
            if clients and "result" in clients and "data" in clients["result"]:
                data["clients"] = {"data": clients["result"]["data"]}

            # Check for missing entities before returning data
            await self._check_missing_entities(data)

            return data

        except Exception as err:
            _LOGGER.error("Error communicating with API: %s", str(err))
            raise UpdateFailed(f"Error communicating with API: {err}")

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Omada Controller from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    try:
        # Create API instance
        api = OmadaAPI(
            base_url=entry.data[CONF_URL],
            username=entry.data[CONF_USERNAME],
            password=entry.data[CONF_PASSWORD],
            site_name=entry.data[CONF_SITE_NAME],
            skip_cert_verify=entry.data.get(CONF_SKIP_CERT_VERIFY, False)
        )

        # Verify authentication
        if not await hass.async_add_executor_job(api.authenticate):
            _LOGGER.error("Could not authenticate with the Omada Controller")
            return False

        # Create update coordinator
        update_interval = entry.data.get(CONF_SCAN_INTERVAL, DEFAULT_UPDATE_INTERVAL.total_seconds())
        coordinator = OmadaDataUpdateCoordinator(
            hass,
            api,
            timedelta(seconds=update_interval)
        )

        # Fetch initial data
        await coordinator.async_config_entry_first_refresh()

        # Store coordinator
        hass.data[DOMAIN][entry.entry_id] = {
            "coordinator": coordinator,
            "api": api,
        }

        # Set up platforms
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
        return True

    except Exception as err:
        _LOGGER.error("Error setting up Omada Controller: %s", str(err))
        return False

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
    return unload_ok