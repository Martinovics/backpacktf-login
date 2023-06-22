import asyncio
import aiohttp
from bs4 import BeautifulSoup
from http.cookies import SimpleCookie
from interfaces.IBackpackLogin import IBackpackLogin




class BackpackLogin(IBackpackLogin):

    MAX_SLEEP_TIME: int = 30 * 60

    def __init__(self, max_login_tries: int = 100):
        self.__session: aiohttp.ClientSession | None = None
        self.__max_login_tries = max_login_tries

        self.__backpack_ready = asyncio.Event()
        self.__backpack_not_ready = asyncio.Event()
        self.__backpack_not_ready.set()


    @property
    def backpack_ready(self) -> asyncio.Event:
        return self.__backpack_ready

    @property
    def backpack_not_ready(self) -> asyncio.Event:
        return self.__backpack_not_ready

    @backpack_ready.setter
    def backpack_ready(self, is_set: bool):
        if is_set:
            self.__backpack_ready.set()
            self.__backpack_not_ready.clear()
        else:
            self.__backpack_ready.clear()
            self.__backpack_not_ready.set()


    def set_session(self, session: aiohttp.ClientSession) -> aiohttp.ClientSession:
        self.__session = session
        return self.__session




    async def __send_request(self, method, url, **kwargs) -> aiohttp.ClientResponse | None:
        kwargs['timeout'] = aiohttp.ClientTimeout(total=30)

        try:
            return await self.__session.request(method, url, **kwargs)
        except asyncio.TimeoutError:
            return




    async def __request_login(self) -> str | None:
        resp: aiohttp.ClientResponse = await self.__send_request('post', 'https://backpack.tf/login')
        data: str = (await resp.read()).decode(encoding='utf-8', errors='ignore')
        if not resp or resp.status != 200:
            return

        data: str = (await resp.read()).decode(encoding='utf-8', errors='ignore')
        return data


    async def __request_openid(self, login_request_data: str) -> aiohttp.ClientResponse | None:
        if login_request_data is None:
            return

        soup = BeautifulSoup(login_request_data, "lxml")
        inputs = soup.find("form", id="openidForm").find_all('input')
        payload = {field['name']: field['value'] for field in inputs if 'name' in field.attrs}

        resp: aiohttp.ClientResponse = await self.__send_request(
            'post', 'https://steamcommunity.com/openid/login', data=payload, allow_redirects=False
        )
        if not resp or resp.status != 302:
            return

        return resp


    async def __request_location_1(self, openid_request_data: aiohttp.ClientResponse) -> aiohttp.ClientResponse | None:
        if openid_request_data is None:
            return

        resp: aiohttp.ClientResponse = await self.__send_request(
            'get', openid_request_data.headers['Location'], allow_redirects=False
        )
        if not resp or resp.status != 301:
            return

        return resp


    async def __request_location_2(self, location_1_request_data: aiohttp.ClientResponse) -> aiohttp.ClientResponse | None:
        if location_1_request_data is None:
            return

        resp: aiohttp.ClientResponse = await self.__send_request(
            'get', location_1_request_data.headers['Location'], allow_redirects=False
        )
        if not resp or resp.status != 302:
            return

        stack_cookies = SimpleCookie()
        for cookie in resp.headers.getall('Set-Cookie'):
            if 'Max-Age=0;' not in cookie:  # 2 empty, 2 not-empty cookies
                # there's a problem with the [] in the cookie keys --> replace them
                stack_cookies.load(cookie.replace('[', '%5B').replace(']', '%5D'))

        self.__session.cookie_jar.update_cookies(stack_cookies)

        return resp




    async def __login_pipeline(self) -> bool:
        data = await self.__request_login()
        data = await self.__request_openid(data)
        data = await self.__request_location_1(data)
        data = await self.__request_location_2(data)

        if data:
            self.backpack_ready = True
        else:
            self.backpack_ready = False

        return self.backpack_ready.is_set()


    async def __login(self) -> None:
        sleep_multiplier = 1
        for i in range(1, self.__max_login_tries + 1):

            if not await self.__login_pipeline():
                if i == 1:
                    sleep_time = 1 * 60
                elif i == 2:
                    sleep_time = 5 * 60
                else:
                    sleep_time = min(10 * 60 * sleep_multiplier, self.MAX_SLEEP_TIME)
                    sleep_multiplier += 1

                print( f'Could not login to backpack (try {i}/{self.__max_login_tries}). Retry in {sleep_time // 60} minutes...')
                await asyncio.sleep(sleep_time)

            else:
                return


    def backpack_login(self) -> None:
        asyncio.ensure_future(self.__login())
