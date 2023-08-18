import logging
import asyncio
import async_timeout
import re
import rsa
import base64
import binascii

# Const values
_LOGIN_TIMEOUT_SECONDS = 5

# Logger
_LOGGER = logging.getLogger(__name__)

class TPCError(Exception):
    def __init__(self, msg=''):
        _LOGGER.error(msg)

class MR6400:
    def __init__(self, hostname, websession):
        self.hostname = hostname
        self.websession = websession
        self._encryptedUsername = None
        self._encryptedPassword = None
        self.token = None

    def _baseurl(self):
        return "http://{}/".format(self.hostname)

    def _url(self, path):
        return self._baseurl + path

    async def logout(self):
        self.websession = None
        self.token = None

    def encryptDataRSA(self, data, nn, ee):
        public_key = rsa.PublicKey(int(nn, 16), int(ee,16))
        encrypted_data = rsa.encrypt(data, public_key)
        encrypted_hex = binascii.hexlify(encrypted_data).decode('utf-8')
        return encrypted_hex

    async def encryptString(self, value, nn, ee):
        encoded = base64.b64encode(value.encode("utf-8"))
        return self.encryptDataRSA(encoded, nn, ee)    

    async def encryptCredentials(self, username, password):
        try:
            async with async_timeout.timeout(_LOGIN_TIMEOUT_SECONDS):
                url = self._url('cgi/getParm')
                headers = { 'Referer': self._baseurl }

                _LOGGER.info(url)
                async with self.websession.post(url, headers=headers) as response:
                    if response.status != 200:
                        raise TPCError("Invalid encryption key request, status: " + str(response.status))
                    responseText = await response.text()
                    eeExp = re.compile(r'(?<=ee=")(.{5}(?:\s|.))', re.IGNORECASE)
                    eeString = eeExp.search(responseText)
                    if eeString:
                        ee = eeString.group(1) 
                    nnExp = re.compile(r'(?<=nn=")(.{255}(?:\s|.))', re.IGNORECASE)
                    nnString = nnExp.search(responseText)
                    if nnString:
                        nn = nnString.group(1)   
        except (asyncio.TimeoutError, acyncio.ClientError, TPCError):
            raise TPCError("Could not retrieve encryption key")
        
        _LOGGER.debug("ee: {0} nn: {1}".format(ee, nn))  
        
        self._encryptedUsername = await self.encryptString(username, nn, ee)
        _LOGGER.debug("Encrypted username: {0}".format(self._encryptedUsername))

        self._encryptedPassword = await self.encryptString(password, nn, ee)
        _LOGGER.debug("Encrypted password: {0}".format(self._encryptedPassword))

        await asyncio.sleep(0.1)

    
    async def login(self, username, password):
        try:
            await self.encryptCredentials(username, password)
            async with async_timeout.timeout(_LOGIN_TIMEOUT_SECONDS):
                url = self._url('cgi/login')
                params = {'UserName': self._encryptedUsername, 'Passwd': self._encryptedPassword, 'Action': '1', 'LoginStatus':'0' }
                headers= { 'Referer': self._baseurl }

                _LOGGER.info(url)
                async with self.websession.post(url, params=params, headers=headers) as response:
                    if response.status != 200:
                        raise TPCError("Invalid login request")
                    hasSessionId = False
                    for cookie in self.websession.cookie_jar:
                        if cookie["domain"] == self.hostname and cookie.key == 'JSESSIONID':
                            hasSessionId = True
                            _LOGGER.debug("Session id: %s", cookie.value)
                    if not hasSessionId:
                        raise TPCError("Inavalid credentials")

                await self.getToken()

        except (asyncio.TimeoutError, asyncio.ClientError, TPCError):
            raise TPCError("Could not login")

    async def getToken(self):
        try:
            async with async_timeout.timeout(_LOGIN_TIMEOUT_SECONDS):
                url = self._url('')
                _LOGGER.info("Token url %s", url)
                async with self.websession.get(url) as response:
                    if response.status != 200:
                        raise TPCError("Invalid token request, status: " + str(response.status))
                    else:
                        _LOGGER.debug("Valid token request")
                    # parse the html response to find the token
                    responseText = await response.text()
                    p = re.compile(r'(?<=token=")(.{29}(?:\s|.))', re.IGNORECASE)
                    m = p.search(responseText)
                    if m:
                        _LOGGER.debug("Token id: %s", m.group(1) )
                        self.token = m.group(1) 

        except (asyncio.TimeoutError, asyncio.ClientError, TPCError):
            raise TPCError("Could not retrieve token")

    async def sms(self, phone, message):
        url = self._url('cgi')
        params = { '2': '' }
        data = "[LTE_SMS_SENDNEWMSG#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\nindex=1\r\nto={0}\r\ntextContent={1}\r\n".format(phone, message)
        headers= { 'Referer': self._baseurl, 'TokenID': self.token }
        async with self.websession.post(url, params=params, data=data, headers=headers) as response:
            if response.status != 200:
                raise TPCError("Failed sending SMS")
