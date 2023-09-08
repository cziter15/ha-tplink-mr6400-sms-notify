from vars import *
from devices import MR6400
import voluptuous as vol
import homeassistant.helpers.config_validation as cv
from homeassistant.components.notify import (ATTR_TARGET, PLATFORM_SCHEMA, BaseNotificationService)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
	vol.Required(CONF_ROUTER_IP): cv.string,
	vol.Required(CONF_ROUTER_PWD): cv.string,
	vol.Required(CONF_ROUTER_USERNAME, default="admin"): cv.string
})

def get_service(hass, config, discovery_info=None):
	return KSSMSNotificationService(config)

class KSSMSNotificationService(BaseNotificationService):
	def __init__(self, config):
		self.router_ip = config.get(CONF_ROUTER_IP)
		self.router_pwd = config.get(CONF_ROUTER_PWD)
		self.router_client = MR6400(config.get(CONF_ROUTER_IP), ROUTER_USERNAME, config.get(CONF_ROUTER_PWD))

	async def async_send_message(self, message, **kwargs):
		phone_numbers = kwargs.get(ATTR_TARGET)
		await self.router_client.login()
		await self.router_client.send_message(phone_numbers, message)
		await self.router_client.logout()