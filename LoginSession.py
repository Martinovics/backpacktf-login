import asyncio
from classes.SteamLogin import SteamLogin
from classes.BackpackLogin import BackpackLogin
from interfaces.ISteamLogin import ISteamLogin
from interfaces.IBackpackLogin import IBackpackLogin
from utils.Credentials import Credentials

from utils.Config import Config as cfg






class LoginSession:

    def __init__(self, steam_login: ISteamLogin, backpack_login: IBackpackLogin):
        self.__steam_login = steam_login
        self.__backpack_login = backpack_login


    async def close_session(self) -> None:
        if not self.__steam_login.session.closed:
            await self.__steam_login.session.close()


    async def login(self) -> None:
        await self.__steam_login.steam_login()
        await self.__steam_login.steam_ready.wait()
        print('logged in to steam')

        self.__backpack_login.set_session(self.__steam_login.session)
        self.__backpack_login.backpack_login()
        await self.__backpack_login.backpack_ready.wait()
        print('logged in to backpack')






async def main() -> None:

    steam_login: ISteamLogin = SteamLogin(Credentials(cfg.username, cfg.password, cfg.shared_secret))
    backpack_login = BackpackLogin()

    login_session = LoginSession(steam_login, backpack_login)
    await login_session.login()


    await asyncio.sleep(20)


    await login_session.close_session()






if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main())
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        pass
        # cleanup
