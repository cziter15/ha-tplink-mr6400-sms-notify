import logging
import aiohttp

import voluptuous as vol
import homeassistant.helpers.config_validation as cv
from homeassistant.components.notify import (ATTR_TARGET, PLATFORM_SCHEMA, BaseNotificationService)
from .tpclient import *

# Const values
MAX_LOGIN_RETRIES = 3
ROUTER_USERNAME = "admin"

# Config names
CONF_ROUTER_IP = 'router_ip'
CONF_ROUTER_PWD = 'router_pwd'

# Extend PLATFORM_SCHEMA for config params
PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_ROUTER_IP): cv.string,
    vol.Required(CONF_ROUTER_PWD): cv.string,
})

# Logger
_LOGGER = logging.getLogger(__name__)

def get_service(hass, config, discovery_info=None):
    return MR6400SMSNotificationService(config)

class MR6400SMSNotificationService(BaseNotificationService):
    def __init__(self, config):
        self.router_ip = config.get(CONF_ROUTER_IP)
        self.router_pwd = config.get(CONF_ROUTER_PWD)

    async def perform_logout(self, tpc):
        try:
            await tpc.logout()
        except TPCError:
            _LOGGER.warning("Failed to logout from the TP")

    async def perform_modem_login(self, tpc, password):
        retries = 0
        while retries < MAX_LOGIN_RETRIES:
            try:
                await tpc.login(ROUTER_USERNAME, password)
                break  # Successful login, exit retry loop
            except TPCError:
                retries += 1
                if retries < MAX_LOGIN_RETRIES:
                    _LOGGER.warning("Retrying login...")
                    await asyncio.sleep(1)  # Wait before retrying
                else:
                    raise TPCError("Login failed after retries")

    async def async_send_message(self, message, **kwargs):
        phone_numbers = kwargs.get(ATTR_TARGET)

        async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as websession:
            tpc = MR6400(self.router_ip, websession)
            try:
                await self.perform_login(tpc, self.router_pwd)
                for phone in phone_numbers:
                    try:
                        await tpc.sms(phone, message)
                        _LOGGER.info("Sent SMS to %s: %s", phone, message)
                    except TPCError:
                        _LOGGER.error("Unable to send to %s", phone)
            except TPCError as e:
                _LOGGER.error("Error communicating with MR6400: %s", str(e))
            finally:
                await self.perform_logout(client)