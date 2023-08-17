
import logging
import re
from functools import wraps
from datetime import datetime
import asyncio
from aiohttp.client_exceptions import ClientError
import async_timeout
import attr
import base64
import rsa
import binascii

import voluptuous as vol

from homeassistant.components.notify import (ATTR_TARGET, PLATFORM_SCHEMA, BaseNotificationService)

TIMEOUT = 3
LOGIN_TIMEOUT = 300

class Error(Exception):
    """Base class for all exceptions."""

def rsaEncrypt(data, nn, ee):
    n = int(nn, 16)
    e = int(ee, 16)
    public_key = rsa.PublicKey(n, e)
    encrypted_data = rsa.encrypt(bytes(data, 'utf-8'), public_key)
    encrypted_hex = binascii.hexlify(encrypted_data).decode('utf-8')
    return encrypted_hex

def autologin(function, timeout=TIMEOUT, login_timeout=LOGIN_TIMEOUT):
    # Decorator that will try to login and redo an action before failing.
    @wraps(function)
    async def wrapper(self, *args, **kwargs):
        try:
            async with async_timeout.timeout(timeout):
                return await function(self, *args, **kwargs)
        except (asyncio.TimeoutError, ClientError, Error):
            pass

        _LOGGER.debug("autologin")
        try:
            async with async_timeout.timeout(login_timeout):
                await self.login()
                return await function(self, *args, **kwargs)
        except (asyncio.TimeoutError, ClientError, Error):
            raise Error(str(function))

    return wrapper


@attr.s
class MR6400:
    hostname = attr.ib()
    websession = attr.ib()

    username = attr.ib(default="admin")
    password = attr.ib(default=None)
    token = attr.ib(default=None)

    _encryptedUsername = None;
    _encryptedPassword = None;

    @property
    def _baseurl(self):
        return "http://{}/".format(self.hostname)

    def _url(self, path):
        return self._baseurl + path

    async def logout(self):
        self.websession = None
        self.token = None

    async def encryptString(self, value, nn, ee):
        value64 = base64.b64encode(value.encode("utf-8"))
        return rsaEncrypt(value64.decode('UTF-8'), nn, ee)    

    async def encryptCredentials(self, password=None, username=None):
        if password is None:
            password = self.password
        else:
            self.password = password

        if username is None:
            username = self.username
        else:
            self.username = username

        try:
            async with async_timeout.timeout(LOGIN_TIMEOUT):
                url = self._url('cgi/getParm')
                headers= { 'Referer': self._baseurl }

                _LOGGER.info(url)
                async with self.websession.post(url, headers=headers) as response:
                    if response.status != 200:
                        _LOGGER.error("Invalid encryption key request")
                        raise Error()
                    responseText = await response.text()
                    eeExp = re.compile(r'(?<=ee=")(.{5}(?:\s|.))', re.IGNORECASE)
                    eeString = eeExp.search(responseText)
                    if eeString:
                        ee = eeString.group(1) 
                    nnExp = re.compile(r'(?<=nn=")(.{255}(?:\s|.))', re.IGNORECASE)
                    nnString = nnExp.search(responseText)
                    if nnString:
                        nn = nnString.group(1)   
        except (asyncio.TimeoutError, ClientError, Error):
            raise Error("Could not retrieve encryption key")
        
        _LOGGER.debug("ee: {0} nn: {1}".format(ee, nn))  
        
        self._encryptedUsername = await self.encryptString(username, nn, ee)
        _LOGGER.debug("Encrypted username: {0}".format(self._encryptedUsername))

        self._encryptedPassword = await self.encryptString(password, nn, ee)
        _LOGGER.debug("Encrypted password: {0}".format(self._encryptedPassword))

        # TODO: without this sleep there's a strange behaviour in the following network request.
        # I need to understand if the problem is caused by the router or the aiohttp API
        await asyncio.sleep(0.1)

    
    async def login(self, password=None, username=None):
        try:
            await self.encryptCredentials(password, username)
            async with async_timeout.timeout(LOGIN_TIMEOUT):
                url = self._url('cgi/login')
                params = {'UserName': self._encryptedUsername, 'Passwd': self._encryptedPassword, 'Action': '1', 'LoginStatus':'0' }
                headers= { 'Referer': self._baseurl }

                _LOGGER.info(url)
                async with self.websession.post(url, params=params, headers=headers) as response:
                    if response.status != 200:
                        _LOGGER.error("Invalid login request")
                        raise Error()
                    hasSessionId = False
                    for cookie in self.websession.cookie_jar:
                        if cookie["domain"] == self.hostname and cookie.key == 'JSESSIONID':
                            hasSessionId = True
                            _LOGGER.debug("Session id: %s", cookie.value)
                    if not hasSessionId:
                        raise Error("Inavalid credentials")

                await self.getToken()

        except (asyncio.TimeoutError, ClientError, Error):
            raise Error("Could not login")

    async def getToken(self):
        try:
            async with async_timeout.timeout(LOGIN_TIMEOUT):
                url = self._url('')
                _LOGGER.info("Token url %s", url)
                async with self.websession.get(url) as response:
                    if response.status != 200:
                        _LOGGER.error("Invalid token request, status: %d", response.status)
                        raise Error()
                    else:
                        _LOGGER.debug("Valid token request")
                    # parse the html response to find the token
                    responseText = await response.text()
                    p = re.compile(r'(?<=token=")(.{29}(?:\s|.))', re.IGNORECASE)
                    m = p.search(responseText)
                    if m:
                        _LOGGER.debug("Token id: %s", m.group(1) )
                        self.token = m.group(1) 
        

        except (asyncio.TimeoutError, ClientError, Error):
            raise Error("Could not retrieve token")

    @autologin
    async def sms(self, phone, message):
        url = self._url('cgi')
        params = { '2': '' }
        data = "[LTE_SMS_SENDNEWMSG#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\nindex=1\r\nto={0}\r\ntextContent={1}\r\n".format(phone, message)
        headers= { 'Referer': self._baseurl, 'TokenID': self.token }
        async with self.websession.post(url, params=params, data=data, headers=headers) as response:
            if response.status != 200:
                raise Error("Failed sending SMS")

class Modem(MR6400):
    """Class for any modem."""

_LOGGER = logging.getLogger(__name__)

def get_service(hass, config, discovery_info=None):
    return MR6400SMSNotificationService(config)

class MR6400SMSNotificationService(BaseNotificationService):
    """Implementation of a notification service for the MR6400SMS service."""

    def __init__(self, config):
        """Initialize the service."""
        self.router_ip = "192.168.1.1"
        self.router_pwd = "kill1212"

    async def async_send_message(self, message, **kwargs):
        phone_numbers = kwargs.get(ATTR_TARGET)

        async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as websession:
            modem = tpmodem.Modem(hostname=self.router_ip, websession=websession)
            try:
                await self.perform_modem_login(modem, self.router_pwd)
                for phone in phone_numbers:
                    try:
                        await modem.sms(phone=phone, message=message)
                        self.logger.info("Sent SMS to %s: %s", phone, message)
                    except tpmodem.Error:
                        self.logger.error("Unable to send to %s", phone)
            except tpmodem.Error as e:
                self.logger.error("Error communicating with the modem: %s", str(e))
            finally:
                await self.perform_modem_logout(modem)
                return web.Response(text='Success')
            return web.Response(text='Error')
