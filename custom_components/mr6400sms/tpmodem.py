import logging
import attr
import asyncio
import async_timeout
import re
import rsa
import base64
import binascii

from functools import wraps
from datetime import datetime
from aiohttp.client_exceptions import ClientError

_LOGIN_TIMEOUT_SECONDS = 5

_LOGGER = logging.getLogger(__name__)

class ModemError(Exception):
    def __init__(self, msg=''):
        _LOGGER.error(msg)

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

    def encryptDataRSA(data, nn, ee):
        n = int(nn, 16)
        e = int(ee, 16)
        public_key = rsa.PublicKey(n, e)
        encrypted_data = rsa.encrypt(bytes(data, 'utf-8'), public_key)
        encrypted_hex = binascii.hexlify(encrypted_data).decode('utf-8')
        return encrypted_hex

    async def encryptString(self, value, nn, ee):
        value64 = base64.b64encode(value.encode("utf-8"))
        return encryptDataRSA(value64.decode('UTF-8'), nn, ee)    

    async def encryptCredentials(self, password, username):
        try:
            async with async_timeout.timeout(_LOGIN_TIMEOUT_SECONDS):
                url = self._url('cgi/getParm')
                headers = { 'Referer': self._baseurl }

                _LOGGER.info(url)
                async with self.websession.post(url, headers=headers) as response:
                    if response.status != 200:
                        raise ModemError("Invalid encryption key request, status: " + str(response.status))
                    responseText = await response.text()
                    eeExp = re.compile(r'(?<=ee=")(.{5}(?:\s|.))', re.IGNORECASE)
                    eeString = eeExp.search(responseText)
                    if eeString:
                        ee = eeString.group(1) 
                    nnExp = re.compile(r'(?<=nn=")(.{255}(?:\s|.))', re.IGNORECASE)
                    nnString = nnExp.search(responseText)
                    if nnString:
                        nn = nnString.group(1)   
        except (asyncio.TimeoutError, ClientError, ModemError):
            raise ModemError("Could not retrieve encryption key")
        
        _LOGGER.debug("ee: {0} nn: {1}".format(ee, nn))  
        
        self._encryptedUsername = await self.encryptString(username, nn, ee)
        _LOGGER.debug("Encrypted username: {0}".format(self._encryptedUsername))

        self._encryptedPassword = await self.encryptString(password, nn, ee)
        _LOGGER.debug("Encrypted password: {0}".format(self._encryptedPassword))

        await asyncio.sleep(0.1)

    
    async def login(self, password, username):
        try:
            await self.encryptCredentials(password, username)
            async with async_timeout.timeout(_LOGIN_TIMEOUT_SECONDS):
                url = self._url('cgi/login')
                params = {'UserName': self._encryptedUsername, 'Passwd': self._encryptedPassword, 'Action': '1', 'LoginStatus':'0' }
                headers= { 'Referer': self._baseurl }

                _LOGGER.info(url)
                async with self.websession.post(url, params=params, headers=headers) as response:
                    if response.status != 200:
                        raise ModemError("Invalid login request")
                    hasSessionId = False
                    for cookie in self.websession.cookie_jar:
                        if cookie["domain"] == self.hostname and cookie.key == 'JSESSIONID':
                            hasSessionId = True
                            _LOGGER.debug("Session id: %s", cookie.value)
                    if not hasSessionId:
                        raise ModemError("Inavalid credentials")

                await self.getToken()

        except (asyncio.TimeoutError, ClientError, ModemError):
            raise ModemError("Could not login")

    async def getToken(self):
        try:
            async with async_timeout.timeout(LOGIN_TIMEOUT):
                url = self._url('')
                _LOGGER.info("Token url %s", url)
                async with self.websession.get(url) as response:
                    if response.status != 200:
                        raise ModemError("Invalid token request, status: " + str(response.status))
                    else:
                        _LOGGER.debug("Valid token request")
                    # parse the html response to find the token
                    responseText = await response.text()
                    p = re.compile(r'(?<=token=")(.{29}(?:\s|.))', re.IGNORECASE)
                    m = p.search(responseText)
                    if m:
                        _LOGGER.debug("Token id: %s", m.group(1) )
                        self.token = m.group(1) 

        except (asyncio.TimeoutError, ClientError, ModemError):
            raise ModemError("Could not retrieve token")

    async def sms(self, phone, message):
        url = self._url('cgi')
        params = { '2': '' }
        data = "[LTE_SMS_SENDNEWMSG#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\nindex=1\r\nto={0}\r\ntextContent={1}\r\n".format(phone, message)
        headers= { 'Referer': self._baseurl, 'TokenID': self.token }
        async with self.websession.post(url, params=params, data=data, headers=headers) as response:
            if response.status != 200:
                raise ModemError("Failed sending SMS")

class Modem(MR6400):
    """Class for any modem."""
