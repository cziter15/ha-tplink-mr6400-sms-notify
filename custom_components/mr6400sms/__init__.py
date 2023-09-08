"""
This is a directory with Python code for the MR6400 SMS integration.

The service is defined inside the notify.py function.
The router client is implemented in tpclient.py.
"""

from devices import MR6400

import voluptuous as vol
import homeassistant.helpers.config_validation as cv
from homeassistant.components.notify import (ATTR_TARGET, PLATFORM_SCHEMA, BaseNotificationService)

# Const values.
MAX_LOGIN_RETRIES = 3
ROUTER_USERNAME = "admin"

# Config names.
CONF_ROUTER_IP = 'router_ip'
CONF_ROUTER_PWD = 'router_pwd'

# Extend PLATFORM_SCHEMA for config params.
PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
	vol.Required(CONF_ROUTER_IP): cv.string,
	vol.Required(CONF_ROUTER_PWD): cv.string,
})
def get_service(hass, config, discovery_info=None):
	return KSSMSNotificationService(config)

class KSSMSNotificationService(BaseNotificationService):
	def __init__(self, config):
		self.router_ip = config.get(CONF_ROUTER_IP)
		self.router_pwd = config.get(CONF_ROUTER_PWD)
		self.router_client = MR6400(config.get(CONF_ROUTER_IP), "admin", config.get(CONF_ROUTER_PWD))

	async def async_send_message(self, message, **kwargs):
		phone_numbers = kwargs.get(ATTR_TARGET)
		await self.router_client.login()
		await self.router_client.send_message(phone_numbers, message)
		await self.router_client.logout()