import logging
import aiohttp
from .tpmodem import *
import voluptuous as vol

import homeassistant.helpers.config_validation as cv
from homeassistant.components.notify import (ATTR_TARGET, PLATFORM_SCHEMA, BaseNotificationService)

MAX_LOGIN_RETRIES = 3

CONF_ROUTER_IP = 'router_ip'
CONF_ROUTER_PWD = 'router_pwd'

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_ROUTER_IP): cv.string,
    vol.Required(CONF_ROUTER_PWD): cv.string,
})

_LOGGER = logging.getLogger(__name__)

def get_service(hass, config, discovery_info=None):
    return MR6400SMSNotificationService(config)

class MR6400SMSNotificationService(BaseNotificationService):
    def __init__(self, config):
        self.router_ip = config.get(CONF_ROUTER_IP)
        self.router_pwd = config.get(CONF_ROUTER_PWD)

    async def perform_modem_logout(self, modem):
        try:
            await modem.logout()
        except ModemError:
            _LOGGER.warning("Failed to logout from the modem")

    async def perform_modem_login(self, modem, password):
        retries = 0
        while retries < MAX_LOGIN_RETRIES:
            try:
                await modem.login(password=password)
                break  # Successful login, exit retry loop
            except ModemError:
                retries += 1
                if retries < MAX_LOGIN_RETRIES:
                    _LOGGER.warning("Retrying modem login...")
                    await asyncio.sleep(1)  # Wait before retrying
                else:
                    raise ModemError("Modem login failed after retries")

    async def async_send_message(self, message, **kwargs):
        phone_numbers = kwargs.get(ATTR_TARGET)

        async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as websession:
            modem = Modem(hostname=self.router_ip, websession=websession)
            try:
                await self.perform_modem_login(modem, self.router_pwd)
                for phone in phone_numbers:
                    try:
                        await modem.sms(phone=phone, message=message)
                        _LOGGER.info("Sent SMS to %s: %s", phone, message)
                    except ModemError:
                        _LOGGER.error("Unable to send to %s", phone)
            except ModemError as e:
                _LOGGER.error("Error communicating with the modem: %s", str(e))
            finally:
                await self.perform_modem_logout(modem)