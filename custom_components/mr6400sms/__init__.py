import voluptuous as vol
import homeassistant.helpers.config_validation as cv
from homeassistant.components.notify import (ATTR_TARGET, PLATFORM_SCHEMA, BaseNotificationService)

from .devices.mr6400 import MR6400

# Config names.
CONF_ROUTER_IP = 'router_ip'
CONF_ROUTER_PWD = 'router_pwd'
CONF_ROUTER_USERNAME = 'router_username'

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
	vol.Required(CONF_ROUTER_IP): cv.string,
	vol.Required(CONF_ROUTER_PWD): cv.string,
	vol.Required(CONF_ROUTER_USERNAME, default="admin"): cv.string
})

def get_service(hass, config, discovery_info=None):
	return KSSMSNotificationService(config)

class KSSMSNotificationService(BaseNotificationService):
	def __init__(self, config):
		self.router_client = MR6400(config.get(CONF_ROUTER_IP), config.get(CONF_ROUTER_USERNAME), config.get(CONF_ROUTER_PWD))

	async def async_send_message(self, message, **kwargs):
		phone_numbers = kwargs.get(ATTR_TARGET)
		await self.router_client.login()
		await self.router_client.send_message(phone_numbers, message)
		await self.router_client.logout()