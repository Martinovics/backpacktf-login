import time
import aiohttp
import asyncio
from bs4 import BeautifulSoup

import tools.utils as utils
import tools.steam_guard as steam_guard
from tools.config import Config as cfg




class Login:
    
    def __init__(self):
        self.session = aiohttp.ClientSession()
        self.logged_in_to_steam = False
        self.logged_in_to_backpack = False




    async def steam_login(self) -> None:
        if self.logged_in_to_steam:
            print("You are already logged in to steam.")
            return

        resp = await self.session.post('https://steamcommunity.com/login/getrsakey/', data={'username': cfg.USERNAME})
        ourRsa = await resp.json()
        
        for cookie in self.session.cookie_jar:
            print(f"{cookie.key}: {cookie.value}")
        

        encoded_password = utils.encode_password(
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


        resp = await self.session.post("https://store.steampowered.com/login/dologin", data=payload)
        resp = await resp.json()
        
        for cookie in self.session.cookie_jar:
            print(f"{cookie.key}: {cookie.value}")
 

        for cookie in self.session.cookie_jar:
            print(cookie.key)
            print(cookie["domain"])

        print(resp)

        
        await self.session.close()
        return



        if not resp['success']:
            err = 'There was an error while logging into steam.'
            if resp.get('message'):
                err += f"\n   Reason: {resp['message']}"
            raise Exception(err)

        for url in resp['transfer_urls']:
            await self.session.post(url, data=resp['transfer_parameters'])


        stm_cookies = self.session.cookie_jar.get_dict()
        self.session.cookie_jar.set(**{"name": "sessionid", "value": stm_cookies['sessionid'], "domain": 'steamcommunity.com'})
        self.session.cookie_jar.set(**{"name": "sessionid", "value": stm_cookies['sessionid'], "domain": 'store.steampowered.com'})

        self.logged_in_to_steam = True
        print('Successfully logged in to steam.')






async def main():
    loginSession = Login()
    await loginSession.steam_login()





if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())

