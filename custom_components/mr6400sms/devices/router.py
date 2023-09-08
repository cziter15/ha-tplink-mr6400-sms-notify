import aiohttp
import asyncio
import logging

_LOGGER = logging.getLogger(__name__)

class RouterException(Exception):
	pass

class Router:
	def __init__(self, hostname, username, password):
		"""
		Initializes the router.
		"""
		self._hostname = hostname
		self._websession = None
		self._username = username
		self._password = password
		self._baseurl = "http://{}/".format(self._hostname)
		self._maxRetries = 3

	def _buildUrl(self, path):
		"""
		Builds the URL for the router.
		"""
		return self._baseurl + path
	
	async def login(self):
		"""
		Login to the router.
		"""
		await self.logout()
		self._websession = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))
		for retries in range(self._maxRetries):
			try:
				await self._perform_login()
				break
			except Exception as e: #TOOD: Non-general exception
				if retries < self._maxRetries - 1:
					_LOGGER.warning("Retrying login (%d of %d) due to exception {%s}", retries + 1, self._maxRetries, e)
					await asyncio.sleep(1)

	async def logout(self):
		"""
		Logs out the user by closing the web session.
		"""
		if self._websession is not None:
			await self._websession.close()
			self._websession = None
			pass

	async def send_message(self, phone_numbers, message):
		"""
		Sends a message to a list of phone numbers.
		""" 
		for phone in phone_numbers:
			await self._send_sms(phone, message)
			_LOGGER.info("Sent SMS to %s: %s", phone, message)

	async def perform_login(self):
		raise NotImplementedError()