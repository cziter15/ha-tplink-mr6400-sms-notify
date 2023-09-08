from .router import *
import binascii
import base64
import rsa
import re

class MR6400(Router):
	_token = None
	_encryptedPassword = ''
	_encryptedUsername = ''

	def _encryptDataRSA(self, data, nn, ee):
		"""
		Encrypts data with RSA.
		"""
		public_key = rsa.PublicKey(int(nn, 16), int(ee, 16))
		encrypted_data = rsa.encrypt(data, public_key)
		encrypted_hex = binascii.hexlify(encrypted_data).decode('utf-8')
		return encrypted_hex

	def _encryptString(self, value, nn, ee):
		"""
		Encrypts a string with RSA.
		"""
		encoded = base64.b64encode(value.encode("utf-8"))
		return self._encryptDataRSA(encoded, nn, ee)

	def _extractKeyPart(self, responseText, pattern):
		"""
		Extracts the key part from the response text.
		"""
		exp = re.compile(pattern, re.IGNORECASE)
		match = exp.search(responseText)
		return match.group(1) if match else None

	async def _perform_login(self):
		"""
		First, this function reads the encryption key from the router.
		Then, it sends a login request to the router.
		Finally, it retrieves the token from the router.
		The token is required to perform any further operations.
		"""
		url = self._buildUrl('cgi/getParm')
		headers = {'Referer': self._baseurl}

		async with self._websession.post(url, timeout=10, headers=headers) as response:
			if response.status != 200:
				raise RouterException(f"Invalid encryption key request because of status {response.status}")
			
			responseText = await response.text()
			ee = self._extractKeyPart(responseText, r'(?<=ee=")(.{5}(?:\s|.))')
			nn = self._extractKeyPart(responseText, r'(?<=nn=")(.{255}(?:\s|.))')
			
			self._encryptedUsername = self._encryptString(self._username, nn, ee)
			self._encryptedPassword = self._encryptString(self._password, nn, ee)

		url = self._buildUrl('cgi/login')

		params = {
			'UserName': self._encryptedUsername, 
			'Passwd': self._encryptedPassword, 
			'Action': '1', 
			'LoginStatus':'0'
		}
		headers = { 'Referer': self._baseurl }

		async with self._websession.post(url, params=params, headers=headers, timeout=10) as response:
			if response.status != 200:
				raise RouterException("Invalid login request")
			
			cookie = next((cookie for cookie in self._websession.cookie_jar if cookie["domain"] == self._hostname and cookie.key == 'JSESSIONID'), None)
			
			if cookie is None:
				raise RouterException("Invalid credentials")

		url = self._buildUrl('')

		async with self._websession.get(url,timeout=10) as response:
			if response.status != 200:
				raise RouterException("Invalid token request because of status " + str(response.status))
			
			responseText = await response.text()
			p = re.compile(r'(?<=token=")(.{29}(?:\s|.))', re.IGNORECASE)
			m = p.search(responseText)
			
			if m:
				self._token = m.group(1) 
			else:
				raise RouterException("Could not retrieve token")
					
	async def _send_sms(self, phone, message):
		"""
		Sends a message to a phone number.
		"""
		if self._token is None:
			raise RouterException("Token is missing. Please login first.")

		url = self._buildUrl('cgi')
		params = {'2': ''}
		data = ("[LTE_SMS_SENDNEWMSG#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\n"f"index=1\r\nto={phone}\r\ntextContent={message}\r\n")
		headers = {'Referer': self._baseurl, 'TokenID': self._token}

		async with self._websession.post(url, params=params, data=data, headers=headers, timeout=10) as response:
			if response.status != 200:
				raise RouterException("Failed sending SMS")