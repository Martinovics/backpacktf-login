import asyncio
from abc import ABC, abstractmethod

import aiohttp


class IBackpackLogin(ABC):

    @property
    @abstractmethod
    def backpack_ready(self) -> asyncio.Event:
        raise NotImplementedError

    @property
    @abstractmethod
    def backpack_not_ready(self) -> asyncio.Event:
        raise NotImplementedError

    @abstractmethod
    def backpack_login(self) -> bool:
        raise NotImplementedError

    def set_session(self, session: aiohttp.ClientSession) -> aiohttp.ClientSession:
        raise NotImplementedError
