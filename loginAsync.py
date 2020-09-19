import re
import time
import json
import aiohttp
import asyncio
from bs4 import BeautifulSoup
from http.cookies import SimpleCookie

import tools.utils as utils
import tools.steam_guard as steam_guard
from tools.config import Const as const
from tools.config import Config as cfg




class Login:
    
    def __init__(self, session):
        self.session = session
        self.logged_in_to_steam = False
        self.logged_in_to_backpack = False




    def get_session(self):
        return self.session




    async def steam_login(self) -> None:
        if self.logged_in_to_steam:
            print("You are already logged in to steam.")
            return


        resp = await self.session.post('https://steamcommunity.com/login/getrsakey/', data={'username': cfg.USERNAME})
        ourRsa = await resp.json()

        encoded_password = utils.encode_password(
            as_string=True,
            password=cfg.PASSWORD, 
            rsa_modulus=int(ourRsa['publickey_mod'], 16),
            rsa_exponent=int(ourRsa['publickey_exp'], 16)
            )

        try:
            two_factor_code = steam_guard.generate_code(shared_secret=cfg.SHARED_SECRET)
        except Exception:
            err = 'There was an error while logging into steam.'
            raise Exception(err + '\n   Reason: The shared_secret that you have given is incorrect.')


        payload = {
            'username': cfg.USERNAME,
            'password': encoded_password,
            'twofactorcode': two_factor_code,
            'emailauth': '',
            'loginfriendlyname': '',
            'captchagid': '-1',
            'captcha_text': '',
            'emailsteamid': '',
            'remember_login': 'false',
            'rsatimestamp': ourRsa['timestamp'],
            'donotcache': str(int(time.time() * 1000))
            }

        resp = await self.session.post("https://store.steampowered.com/login/dologin", params=payload)
        resp = await resp.json()

        if not resp['success']:
            err = 'There was an error while logging into steam.'
            if resp.get('message'):
                err += f"\n   Reason: {resp['message']}"
            raise Exception(err)

        for url in resp['transfer_urls']:
            await self.session.post(url, data=resp['transfer_parameters'])


        stm_cookies = utils.jar_to_dict(self.session.cookie_jar)

        cookies = SimpleCookie(
            f"sessionid={stm_cookies['sessionid']}; Domain=steamcommunity.com; "
            f"sessionid={stm_cookies['sessionid']}; Domain=store.steampowered.com; "
            )
        
        self.session.cookie_jar.update_cookies(cookies)


        self.logged_in_to_steam = True
        print('Successfully logged in to steam.')




    async def backpack_login(self) -> None:
        if self.logged_in_to_backpack:
            print("You are already logged in to backpack.tf.")
            return

        
        resp = await self.session.post('https://backpack.tf/login')
        if resp.status != 200:
            raise Exception(f"There was an error while logging into backpack.tf.\n   Reason: {resp.status}")
        
        req_url = resp.url
        resp = await resp.read()

        soup = BeautifulSoup(resp.decode(encoding='utf-8', errors='ignore'), "lxml")
        payload = {
            'action': soup.findAll("input", {"name": "action"})[0]['value'],
            'openidmode': soup.findAll("input", {"name": "openid.mode"})[0]['value'],
            'openidparams': soup.findAll("input", {"name": "openidparams"})[0]['value'],
            'nonce': soup.findAll("input", {"name": "nonce"})[0]['value']
            }

        print(utils.jar_to_dict(self.session.cookie_jar))

        resp = await self.session.post(req_url, params=payload)
        if resp.status != 200:
            raise Exception(f"There was an error while logging into backpack.tf.\n   Reason: {resp.status}")


        await asyncio.sleep(1)

        resp = await self.session.get("https://backpack.tf/")
        resp = await resp.read()
        soup = BeautifulSoup(resp.decode(encoding='utf-8', errors='ignore'), 'lxml').find_all("div", class_="username")

        if soup:
            soup = str(soup[0]).replace('\n', '').replace('  ', '')
            steamID64, username = re.findall(r'<a href="/profiles/(.*?)">(.*?)</a>', soup)[0]            

            self.logged_in_to_backpack = True
            print(f"Successfully logged in to backpack.tf as {username} ({steamID64}).")
        else:
            raise Exception("There was an error while logging into backpack.tf.\n   Reason: unknown")




    async def login(self) -> None:
        await self.steam_login()
        await self.backpack_login()
        print('Successfully logged in.')




    async def steam_logout(self) -> None:
        if not self.logged_in_to_steam:
            print("You aren't logged in to steam.")
            return


        cookies = utils.jar_to_dict(self.session.cookie_jar)
        resp = await self.session.post('https://steamcommunity.com/login/logout/', data={'sessionid':cookies['sessionid']})
        
        if resp.status != 200:
            resp = await resp.read()
            raise Exception(f"There was an error while logging out from steam.\n   Reason: {resp}")

        self.logged_in_to_steam = False
        print('Successfully logged out from steam.')
    



    async def backpack_logout(self) -> None:
        if not self.logged_in_to_backpack:
            print("You aren't logged in to backpack.tf.")
            return


        cookies = utils.jar_to_dict(self.session.cookie_jar)
        resp = await self.session.get(f"https://backpack.tf/logout?user-id={cookies['user-id']}")

        if resp.status != 200:
            resp = await resp.read()
            raise Exception(f"There was an error while logging out from backpack.tf.\n   Reason: {resp}")
        
        self.logged_in_to_backpack = False
        print('Successfully logged out from backpack.tf.')




    async def logout(self) -> None:
        await self.steam_logout()
        await self.backpack_logout()
        
        await self.session.close()
        print('Successfully logged out.')






async def main():

    async with aiohttp.ClientSession(headers={'User-Agent': const.USER_AGENT}) as session:

        loginSession = Login(session=session)

        await loginSession.login()
        
        await asyncio.sleep(0.5)
        resp = await loginSession.get_session().get("https://backpack.tf/")
        resp = await resp.read()
        if 'username' in resp.decode(encoding='utf-8', errors='ignore'):
            print('successsss')
        
        await asyncio.sleep(5)
        await loginSession.logout()




if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
