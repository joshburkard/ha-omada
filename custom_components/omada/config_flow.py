"""Config flow for Omada Controller."""
from typing import Any
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import (
    CONF_URL,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
)
from homeassistant.data_entry_flow import FlowResult

from .const import DOMAIN, CONF_SITE_NAME, CONF_SKIP_CERT_VERIFY, DEFAULT_UPDATE_INTERVAL

class OmadaFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a Omada Controller config flow."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        if user_input is None:
            return self.async_show_form(
                step_id="user",
                data_schema=vol.Schema(
                    {
                        vol.Required(CONF_URL): str,
                        vol.Required(CONF_USERNAME): str,
                        vol.Required(CONF_PASSWORD): str,
                        vol.Required(CONF_SITE_NAME): str,
                        vol.Optional(CONF_SKIP_CERT_VERIFY, default=False): bool,
                        vol.Optional(
                            CONF_SCAN_INTERVAL,
                            default=DEFAULT_UPDATE_INTERVAL.total_seconds(),
                        ): int,
                    }
                ),
            )

        return self.async_create_entry(
            title=f"Omada Controller - {user_input[CONF_SITE_NAME]}",
            data=user_input,
        )