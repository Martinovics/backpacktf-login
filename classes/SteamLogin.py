import aiohttp
import steam
import asyncio
from typing import Any
from utils.Credentials import Credentials
from interfaces.ISteamLogin import ISteamLogin




class SteamLogin(steam.Client, ISteamLogin):

    MAX_SLEEP_TIME: int = 30 * 60


    def __init__(self, credentials: Credentials, max_login_tries: int = 100, **options: Any):
        super().__init__(**options)

        self.__credentials = credentials
        self.__max_login_tries = max_login_tries

        self.__steam_ready = asyncio.Event()
        self.__steam_not_ready = asyncio.Event()
        self.__steam_not_ready.set()

        self.__already_logged_in_once = False


    @property
    def steam_ready(self) -> asyncio.Event:
        return self.__steam_ready

    @property
    def steam_not_ready(self) -> asyncio.Event:
        return self.__steam_not_ready

    @steam_ready.setter
    def steam_ready(self, is_set: bool):
        if is_set:
            self.__steam_ready.set()
            self.__steam_not_ready.clear()
        else:
            self.__steam_ready.clear()
            self.__steam_not_ready.set()

    @property
    def session(self) -> aiohttp.ClientSession:
        return self.http.session


    async def on_ready(self) -> None:
        print('steam ready')
        self.steam_ready = self.is_ready()

    async def on_connect(self) -> None:
        self.steam_ready = self.is_ready()

    async def on_disconnect(self) -> None:
        self.steam_ready = self.is_ready()

    async def on_login(self) -> None:
        self.steam_ready = self.is_ready()

    async def on_logout(self) -> None:
        self.steam_ready = self.is_ready()




    async def __login(self) -> None:

        sleep_multiplier = 1
        for i in range(1, self.__max_login_tries + 1):
            try:
                await self.login(  # ez nem ter vissza, mert while true-ban pollolja a ws-t
                    self.__credentials.username,
                    self.__credentials.password,
                    shared_secret=self.__credentials.shared_secret
                )
            except steam.LoginError:
                if i == 1:
                    sleep_time = 1 * 60
                elif i == 2:
                    sleep_time = 5 * 60
                else:
                    sleep_time = min(10 * 60 * sleep_multiplier, self.MAX_SLEEP_TIME)
                    sleep_multiplier += 1

                print(f'Could not login to steam (try {i}/{self.__max_login_tries}). Retry in {sleep_time // 60} minutes...')
                await asyncio.sleep(sleep_time)


    async def steam_login(self) -> None:
        asyncio.ensure_future(self.__login())
