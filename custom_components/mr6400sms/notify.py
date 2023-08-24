import asyncio
import async_timeout
import re
import rsa
import base64
import binascii

from asyncio import TimeoutError
from aiohttp.client_exceptions import ClientError

# Const values
_LOGIN_TIMEOUT_SECONDS = 5

class TPCError(Exception):
    pass

class MR6400:
    def __init__(self, hostname):
        self.hostname = hostname
        self.token = None
        self._encryptedUsername = None
        self._encryptedPassword = None
        self._baseurl = "http://{}/".format(self.hostname)

    def buildUrl(self, path):
        return self._baseurl + path

    async def logout(self):
        self.websession = None
        self.token = None

    def encryptDataRSA(self, data, nn, ee):
        public_key = rsa.PublicKey(int(nn, 16), int(ee,16))
        encrypted_data = rsa.encrypt(data, public_key)
        encrypted_hex = binascii.hexlify(encrypted_data).decode('utf-8')
        return encrypted_hex

    def encryptString(self, value, nn, ee):
        encoded = base64.b64encode(value.encode("utf-8"))
        return self.encryptDataRSA(encoded, nn, ee)

    def extractKeyPart(self, responseText, pattern):
        exp = re.compile(pattern, re.IGNORECASE)
        match = exp.search(responseText)
        return match.group(1) if match else None
    
    async def encryptCredentials(self, username, password):
        try:
            async with async_timeout.timeout(_LOGIN_TIMEOUT_SECONDS):
                url = self.buildUrl('cgi/getParm')
                headers = {'Referer': self._baseurl}
                async with self.websession.post(url, headers=headers) as response:
                    if response.status != 200:
                        raise TPCError("Invalid encryption key request, status: " + str(response.status))
                    responseText = await response.text()
                    ee = self.extractKeyPart(responseText, r'(?<=ee=")(.{5}(?:\s|.))')
                    nn = self.extractKeyPart(responseText, r'(?<=nn=")(.{255}(?:\s|.))')
                    self._encryptedUsername = self.encryptString(username, nn, ee)
                    self._encryptedPassword = self.encryptString(password, nn, ee)
        except (TimeoutError, ClientError, TPCError) as e:
            raise TPCError("Could not retrieve encryption key, reason: " +  str(e))
    
    async def login(self, websession, username, password):
        try:
            self.websession = websession
            await self.encryptCredentials(username, password)
            await asyncio.sleep(0.1)
            async with async_timeout.timeout(_LOGIN_TIMEOUT_SECONDS):
                url = self.buildUrl('cgi/login')
                params = {'UserName': self._encryptedUsername, 'Passwd': self._encryptedPassword, 'Action': '1', 'LoginStatus':'0' }
                headers = { 'Referer': self._baseurl }
                async with self.websession.post(url, params=params, headers=headers) as response:
                    if response.status != 200:
                        raise TPCError("Invalid login request")
                    for cookie in self.websession.cookie_jar:
                        if cookie["domain"] == self.hostname and cookie.key == 'JSESSIONID':
                            await self.getToken()
                            return
                    raise TPCError("Invalid credentials")
        except (TimeoutError, ClientError, TPCError) as e:
            self.websession = None
            raise TPCError("Could not login, reason: " +  str(e))

    async def getToken(self):
        try:
            async with async_timeout.timeout(_LOGIN_TIMEOUT_SECONDS):
                url = self.buildUrl('')
                async with self.websession.get(url) as response:
                    if response.status != 200:
                        raise TPCError("Invalid token request, status: " + str(response.status))
                    responseText = await response.text()
                    p = re.compile(r'(?<=token=")(.{29}(?:\s|.))', re.IGNORECASE)
                    m = p.search(responseText)
                    if m:
                        self.token = m.group(1) 
        except (TimeoutError, ClientError, TPCError) as e:
            raise TPCError("Could not retrieve token, reason: " +  str(e))

    async def sms(self, phone, message):
        url = self.buildUrl('cgi')
        params = { '2': '' }
        data = "[LTE_SMS_SENDNEWMSG#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\nindex=1\r\nto={0}\r\ntextContent={1}\r\n".format(phone, message)
        headers= { 'Referer': self._baseurl, 'TokenID': self.token }
        async with self.websession.post(url, params=params, data=data, headers=headers) as response:
            if response.status != 200:
                raise TPCError("Failed sending SMS")
