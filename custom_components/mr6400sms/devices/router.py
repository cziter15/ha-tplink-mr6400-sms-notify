import aiohttp
import asyncio
import logging

_LOGGER = logging.getLogger(__name__)

class RouterException(Exception):
	pass

class Router:
	def __init__(self, hostname, username, password, maxRetries=3, requestTimeout=10):
		"""
		Initializes the router.
		"""
		self._hostname = hostname
		self._websession = None
		self._username = username
		self._password = password
		self._baseurl = "http://{}/".format(self._hostname)
		self._maxRetries = maxRetries
		self._requestTimeout = requestTimeout

	def _buildUrl(self, path):
		"""
		Builds the URL for the router.
		"""
		return self._baseurl + path

	async def _perform_login(self):
		"""
		This function is overridden in child classes. Implements per-device login flow.
		"""
		pass
	
	async def _perform_logout(self):
		"""
		This function is overridden in child classes. Implements per-device logout flow.
		"""
		pass

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
			except (RouterException, Exception) as e:
				if retries < self._maxRetries - 1:
					_LOGGER.warning("Retrying login (%d of %d) due to exception {%s}", retries + 1, self._maxRetries, e)
					await asyncio.sleep(1)

	async def logout(self):
		"""
		Logs out the user by closing the web session.
		"""
		if self._websession is not None:
			await self._perform_logout()
			await self._websession.close()
			self._websession = None
			pass

	async def send_message(self, phone_numbers, message):
		"""
		Sends a message to a list of given phone numbers.
		""" 
		for phone in phone_numbers:
			await self._send_sms(phone, message)
			_LOGGER.info("Sent SMS to %s: %s", phone, message)