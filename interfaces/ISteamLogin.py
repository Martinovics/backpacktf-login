import asyncio
from abc import ABC, abstractmethod

import aiohttp


class ISteamLogin(ABC):

    @property
    @abstractmethod
    def steam_ready(self) -> asyncio.Event:
        raise NotImplementedError

    @property
    @abstractmethod
    def steam_not_ready(self) -> asyncio.Event:
        raise NotImplementedError

    @property
    @abstractmethod
    def session(self) -> aiohttp.ClientSession:
        raise NotImplementedError

    @abstractmethod
    def steam_login(self) -> None:
        raise NotImplementedError
