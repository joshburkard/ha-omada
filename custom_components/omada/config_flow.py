"""Config flow for Test HA Omada integration."""
import logging
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_URL, CONF_USERNAME, CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
import homeassistant.helpers.config_validation as cv

from .const import DOMAIN, CONF_SITE_NAME, CONF_SKIP_CERT_VERIFY
from .api import OmadaAPI

_LOGGER = logging.getLogger(__name__)

class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Test HA Omada."""

    VERSION = 1

    async def async_step_user(self, user_input=None) -> FlowResult:
        """Handle the initial step."""
        errors = {}

        if user_input is not None:
            try:
                api = OmadaAPI(
                    base_url=user_input[CONF_URL],
                    username=user_input[CONF_USERNAME],
                    password=user_input[CONF_PASSWORD],
                    site_name=user_input[CONF_SITE_NAME],
                    skip_cert_verify=user_input[CONF_SKIP_CERT_VERIFY]
                )

                # Test the connection
                result = await self.hass.async_add_executor_job(api.authenticate)
                if not result:
                    errors["base"] = "cannot_connect"
                else:
                    return self.async_create_entry(
                        title=f"Omada Controller ({user_input[CONF_SITE_NAME]})",
                        data=user_input
                    )

            except Exception as ex:
                _LOGGER.error("Error connecting to Omada Controller: %s", str(ex))
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_URL): str,
                    vol.Required(CONF_USERNAME): str,
                    vol.Required(CONF_PASSWORD): str,
                    vol.Required(CONF_SITE_NAME): str,
                    vol.Optional(CONF_SKIP_CERT_VERIFY, default=False): bool,
                }
            ),
            errors=errors,
        )
