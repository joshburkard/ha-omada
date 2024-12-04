"""API client for Test HA Omada integration."""
import logging
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

_LOGGER = logging.getLogger(__name__)

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

            _LOGGER.debug("Successfully authenticated with Omada Controller")
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

    def get_devices(self):
        """Get all devices from Omada Controller."""
        try:
            url = f"{self.base_url}/{self.omada_id}/api/v2/sites/{self.site_id}/grid/devices"
            _LOGGER.debug("Getting devices from %s", url)
            return self._make_request("GET", url)
        except Exception as e:
            _LOGGER.error("Failed to get devices: %s", str(e))
            return []

    def get_device_ssid_overrides(self, mac: str):
        """Get SSID overrides for an AP device."""
        try:
            url = f"{self.base_url}/{self.omada_id}/api/v2/sites/{self.site_id}/eaps/{mac}"
            _LOGGER.debug("Getting SSID overrides from %s", url)
            response = self._make_request("GET", url)
            if response and "result" in response:
                wlanId = response["result"].get("wlanId", [])
                ssid_overrides = response["result"].get("ssidOverrides", [])

                _LOGGER.debug("Got SSID overrides for device %s: %s", mac, ssid_overrides)
                return ssid_overrides
            return []
        except Exception as e:
            _LOGGER.error("Failed to get SSID overrides for device %s: %s", mac, str(e))
            return []

    def get_device_radio(self, mac: str):
        """Get SSID overrides for an AP device."""
        try:
            url = f"{self.base_url}/{self.omada_id}/api/v2/sites/{self.site_id}/eaps/{mac}"
            _LOGGER.debug("Getting radios from %s", url)
            response = self._make_request("GET", url)
            if response and "result" in response:
                radioSetting2g = response["result"].get("radioSetting2g", []).get("radioEnable", [])
                radioSetting5g = response["result"].get("radioSetting5g", []).get("radioEnable", [])
                ledSetting = response["result"].get("ledSetting", [])

                # _LOGGER.debug("Got radioSetting2g for device %s: %s", mac, radioSetting2g)
                return {
                    "radioSetting2g": radioSetting2g,
                    "radioSetting5g": radioSetting5g,
                    "ledSetting": ledSetting
                }
            return []
        except Exception as e:
            _LOGGER.error("Failed to get SSID overrides for device %s: %s", mac, str(e))
            return []

    def get_known_clients(self):
        """Get all known clients from Omada Controller."""
        try:
            all_clients = []
            current_page = 1
            page_size = 25
            total_rows = None

            while True:
                url = f"{self.base_url}/{self.omada_id}/api/v2/sites/{self.site_id}/insight/clients?currentPage={current_page}&currentPageSize={page_size}"
                _LOGGER.debug("Getting known clients page %s from %s", current_page, url)

                response = self._make_request("GET", url)
                if not response or "result" not in response:
                    break

                # Get total number of rows if we don't have it yet
                if total_rows is None:
                    total_rows = response["result"].get("totalRows", 0)
                    _LOGGER.debug("Total known clients to fetch: %s", total_rows)

                # Get current page's data
                page_data = response["result"].get("data", [])
                all_clients.extend(page_data)

                # Calculate if we need more pages
                clients_so_far = len(all_clients)
                _LOGGER.debug("Fetched %s known clients so far out of %s", clients_so_far, total_rows)

                if clients_so_far >= total_rows or not page_data:
                    break

                current_page += 1

            _LOGGER.debug("Finished fetching all %s known clients", len(all_clients))
            return {
                "errorCode": 0,
                "msg": "Success.",
                "result": {
                    "totalRows": len(all_clients),
                    "data": all_clients
                }
            }

        except Exception as e:
            _LOGGER.error("Failed to get known clients: %s", str(e))
            return []

    def get_online_clients(self):
        """Get all online clients from Omada Controller."""
        try:
            all_clients = []
            current_page = 1
            page_size = 10
            total_rows = None

            while True:
                url = f"{self.base_url}/{self.omada_id}/api/v2/sites/{self.site_id}/clients?currentPage={current_page}&currentPageSize={page_size}&filters.active=true"
                _LOGGER.debug("Getting online clients page %s from %s", current_page, url)

                response = self._make_request("GET", url)
                if not response or "result" not in response:
                    break

                # Get total number of rows if we don't have it yet
                if total_rows is None:
                    total_rows = response["result"].get("totalRows", 0)
                    _LOGGER.debug("Total online clients to fetch: %s", total_rows)

                # Get current page's data
                page_data = response["result"].get("data", [])
                all_clients.extend(page_data)

                # Calculate if we need more pages
                clients_so_far = len(all_clients)
                _LOGGER.debug("Fetched %s online clients so far out of %s", clients_so_far, total_rows)

                if clients_so_far >= total_rows or not page_data:
                    break

                current_page += 1

            _LOGGER.debug("Finished fetching all %s online clients", len(all_clients))
            return {
                "errorCode": 0,
                "msg": "Success.",
                "result": {
                    "totalRows": len(all_clients),
                    "data": all_clients
                }
            }

        except Exception as e:
            _LOGGER.error("Failed to get online clients: %s", str(e))
            return []

    def get_clients(self):
        """Get all clients from Omada Controller."""
        try:
            # Get both known and online clients
            known_clients_response = self.get_known_clients()
            online_clients_response = self.get_online_clients()

            known_clients = known_clients_response.get("result", {}).get("data", [])
            online_clients = online_clients_response.get("result", {}).get("data", [])

            # Create a dictionary of known clients with MAC as key
            known_clients_dict = {client["mac"]: client for client in known_clients}

            # Update known clients with online status and details
            for online_client in online_clients:
                mac = online_client.get("mac")
                if mac in known_clients_dict:
                    # Update known client with online details
                    known_clients_dict[mac].update(online_client)
                    known_clients_dict[mac]["active"] = True
                else:
                    # Add new online client to known clients
                    online_client["active"] = True
                    known_clients_dict[mac] = online_client

            # Set all clients not in online_clients as inactive
            online_macs = {client["mac"] for client in online_clients}
            for mac, client in known_clients_dict.items():
                if mac not in online_macs:
                    client["active"] = False

            # Convert back to list
            all_clients = list(known_clients_dict.values())

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

    def get_networks(self):
        """Get network information."""
        try:
            all_networks = []
            current_page = 1
            page_size = 10

            while True:
                url = f"{self.base_url}/{self.omada_id}/api/v2/sites/{self.site_id}/setting/lan/networks?currentPage={current_page}&currentPageSize={page_size}"
                _LOGGER.debug("Getting networks page %s from %s", current_page, url)

                response = self._make_request("GET", url)
                if not response or "result" not in response:
                    break

                # Get total number of rows if we don't have it yet
                total_rows = response["result"].get("totalRows", 0)
                _LOGGER.debug("Total networks to fetch: %s", total_rows)

                # Get current page's data
                page_data = response["result"].get("data", [])
                all_networks.extend(page_data)

                # Calculate if we need more pages
                networks_so_far = len(all_networks)
                _LOGGER.debug("Fetched %s networks so far out of %s", networks_so_far, total_rows)

                if networks_so_far >= total_rows or not page_data:
                    break

                current_page += 1

            _LOGGER.debug("Finished fetching all %s networks", len(all_networks))
            return {
                "errorCode": 0,
                "msg": "Success.",
                "result": {
                    "totalRows": len(all_networks),
                    "data": all_networks
                }
            }

        except Exception as e:
            _LOGGER.error("Failed to get networks: %s", str(e))
            return {"result": {"data": []}}

    def get_ip_groups(self):
        """Get IP group information."""
        try:
            url = f"{self.base_url}/{self.omada_id}/api/v2/sites/{self.site_id}/setting/profiles/groups"
            _LOGGER.debug("Getting IP groups from %s", url)
            response = self._make_request("GET", url)
            _LOGGER.debug("IP groups response: %s", response)
            return response
        except Exception as e:
            _LOGGER.error("Failed to get IP groups: %s", str(e))
            return {"result": {"data": []}}

    def get_wlans(self):
        """Get WLAN information."""
        try:
            url = f"{self.base_url}/{self.omada_id}/api/v2/sites/{self.site_id}/setting/wlans"
            _LOGGER.debug("Getting WLANs from %s", url)
            response = self._make_request("GET", url)
            _LOGGER.debug("WLANs response: %s", response)
            return response
        except Exception as e:
            _LOGGER.error("Failed to get WLANs: %s", str(e))
            return {"result": {"data": []}}

    def get_ssids_for_wlan(self, wlan_id):
        """Get SSIDs for a specific WLAN."""
        try:
            # Initialize pagination parameters
            all_ssids = []
            current_page = 1
            page_size = 10

            while True:
                url = f"{self.base_url}/{self.omada_id}/api/v2/sites/{self.site_id}/setting/wlans/{wlan_id}/ssids?currentPage={current_page}&currentPageSize={page_size}"
                _LOGGER.debug("Getting SSIDs for WLAN %s from %s", wlan_id, url)

                response = self._make_request("GET", url)
                if not response or "result" not in response:
                    break

                # Get total number of rows if we don't have it yet
                total_rows = response["result"].get("totalRows", 0)
                _LOGGER.debug("Total SSIDs to fetch: %s", total_rows)

                # Get current page's data
                page_data = response["result"].get("data", [])
                all_ssids.extend(page_data)

                # Calculate if we need more pages
                ssids_so_far = len(all_ssids)
                _LOGGER.debug("Fetched %s SSIDs so far out of %s", ssids_so_far, total_rows)

                if ssids_so_far >= total_rows or not page_data:
                    break

                current_page += 1

            return all_ssids
        except Exception as e:
            _LOGGER.error("Failed to get SSIDs for WLAN %s: %s", wlan_id, str(e))
            return []

    def get_all_ssids(self):
        """Get all SSIDs from all WLANs."""
        try:
            all_ssids = []
            wlans_response = self.get_wlans()

            if wlans_response and "result" in wlans_response:
                wlans = wlans_response.get("result", {}).get("data", [])

                for wlan in wlans:
                    wlan_id = wlan.get("id")
                    wlan_name = wlan.get("name", "Unknown WLAN")

                    if wlan_id:
                        ssids = self.get_ssids_for_wlan(wlan_id)
                        for ssid in ssids:
                            ssid["wlanName"] = wlan_name
                            ssid["wlanId"] = wlan_id
                        all_ssids.extend(ssids)

            return {
                "errorCode": 0,
                "msg": "Success.",
                "result": {
                    "data": all_ssids
                }
            }
        except Exception as e:
            _LOGGER.error("Failed to get all SSIDs: %s", str(e))
            return {"result": {"data": []}}

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

    def update_device_ssid_overrides(self, device_mac: str, payload: dict) -> bool:
        """Update SSID overrides for an AP device."""
        try:
            url = f"{self.base_url}/{self.omada_id}/api/v2/sites/{self.site_id}/eaps/{device_mac}"
            _LOGGER.debug("Updating SSID overrides at %s with payload: %s", url, payload)

            # Verify payload has required structure
            #if "ssidOverrides" not in payload or "wlanId" not in payload:
            #    raise ValueError("Payload must contain ssidOverrides and wlanId")

            response = self._make_request("PATCH", url, json=payload)
            return response.get("errorCode", -1) == 0

        except Exception as e:
            _LOGGER.error("Failed to update SSID overrides for device %s: %s", device_mac, str(e))
            return False

    def update_device_radio(self, device_mac: str, payload: dict) -> bool:
        """Update SSID overrides for an AP device."""
        try:
            url = f"{self.base_url}/{self.omada_id}/api/v2/sites/{self.site_id}/eaps/{device_mac}"
            _LOGGER.debug("Updating SSID overrides at %s with payload: %s", url, payload)

            response = self._make_request("PATCH", url, json=payload)
            return response.get("errorCode", -1) == 0

        except Exception as e:
            _LOGGER.error("Failed to update SSID overrides for device %s: %s", device_mac, str(e))
            return False
