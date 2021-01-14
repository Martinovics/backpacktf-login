import re
import time
import aiohttp
import asyncio
from yarl import URL
from bs4 import BeautifulSoup

import tools.utils as utils
import tools.steam_guard as steam_guard
from tools.config import Const as const
from tools.config import Config as cfg




class Login:

    def __init__(self, session):
        self.session = session
        self.stm_logged_in = False
        self.bptf_logged_in = False




    def get_session(self):
        return self.session




    async def steam_login(self) -> None:

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

        resp = await self.session.post("https://store.steampowered.com/login/dologin", data=payload)
        resp = await resp.json()

        if not resp['success']:
            err = 'There was an error while logging into steam.'
            if resp.get('message'):
                err += f"\n   Reason: {resp['message']}"
            raise Exception(err)

        for url in resp['transfer_urls']:
            await self.session.post(url, data=resp['transfer_parameters'])

        cookies = self.set_cookie(const.COMMUNITY_URL[8:], const.STORE_URL[8:])
        self.session.cookie_jar.update_cookies(cookies, URL(const.COMMUNITY_URL))


        # check whether we are really logged in
        resp = await self.session.get('https://steamcommunity.com/')
        resp = await resp.read()
        resp = re.sub(r'[\r\n\t]', '', resp.decode(encoding='utf-8', errors='ignore')).replace('  ', '')

        username = re.findall(r'data-tooltip-content=".submenu_username">(.*?)</a>', resp)
        steamID64 = re.findall(r'g_steamID = "(.*?)";', resp)

        if username and steamID64:
            print(f'Successfully logged in to steam as {username[-1]} ({steamID64[-1]}).')
        else:
            raise Exception("There was an error while logging into steam.\n   Reason: unknown")




    async def backpack_login(self) -> None:

        print(list(self.session.cookie_jar))
        print()

        resp = await self.session.post('https://backpack.tf/login/')
        if resp.status != 200:
            raise Exception(f"There was an error while logging into backpack.tf.\n   Reason: {resp.status}")

        print(list(self.session.cookie_jar))
        print()

        await asyncio.sleep(0.2)

        cookies = self.set_cookie('backpack.tf', '.backpack.tf')
        self.session.cookie_jar.update_cookies(cookies, URL('.backpack.tf'))

        for morsel in list(self.session.cookie_jar):
            if morsel['domain'] == 'backpack.tf':
                morsel['domain'] = '.backpack.tf'

        print(list(self.session.cookie_jar))
        print()


        soup = BeautifulSoup((await resp.read()).decode(encoding='utf-8', errors='ignore'), "lxml")
        payload = {field['name']: field['value'] for field in soup.find("form", id="openidForm").find_all('input') if 'name' in field.attrs}
        resp = await self.session.post('https://steamcommunity.com/openid/login', data=payload, headers={"Content-Type": "multipart/form-data"})
        if resp.status != 200:
            raise Exception(f"There was an error while logging into backpack.tf.\n   Reason: {resp.status}")

        print(list(self.session.cookie_jar))
        print()

        try:
            steamID, _, username = re.findall(r'<a href="https://steamcommunity.com/profiles/(.*?)/" data-miniprofile="(.*?)">(.*?)</a>',
                                              (await resp.read()).decode(encoding='utf-8', errors='ignore'))[0]

            print(f'Successfully logged in to backpack.tf as {username} ({steamID}).')

        except Exception:
            raise Exception(f"There was an error while logging into backpack.tf.\n   Reason: {resp.status}")


        await asyncio.sleep(0.2)

        '''
        resp = await self.session.get('https://backpack.tf/settings')
        print((await resp.read()).decode(encoding='utf-8', errors='ignore'))
        '''

        '''
        payload = {
            'item_name': 'Mann Co. Supply Crate Key',
            'intent': 'sell',
            'blanket': '1',
            'user-id': utils.jar_to_dict(self.session.cookie_jar)['user-id']
        }
        resp = await self.session.post('https://backpack.tf/classifieds/alerts', data=payload)
        print(len((await resp.read()).decode(encoding='utf-8', errors='ignore')))
        '''


    async def login(self) -> None:
        await self.steam_login()
        await self.backpack_login()
        print('Successfully logged in.')




    async def steam_logout(self) -> None:

        cookies = utils.jar_to_dict(self.session.cookie_jar)
        resp = await self.session.post('https://steamcommunity.com/login/logout/', data={'sessionid': cookies['sessionid']})

        if resp.status != 200:
            resp = await resp.read()
            raise Exception(f"There was an error while logging out from steam.\n   Reason: {resp}")

        print('Successfully logged out from steam.')




    async def backpack_logout(self) -> None:

        cookies = utils.jar_to_dict(self.session.cookie_jar)
        resp = await self.session.get(f"https://backpack.tf/logout?user-id={cookies['user-id']}")

        if resp.status != 200:
            resp = await resp.read()
            raise Exception(f"There was an error while logging out from backpack.tf.\n   Reason: {resp}")

        print('Successfully logged out from backpack.tf.')




    async def logout(self) -> None:
        await self.steam_logout()
        await self.backpack_logout()

        await asyncio.sleep(0.1)
        await self.session.close()
        print('Successfully logged out.')




    def set_cookie(self, prev_domain, new_domain):
        cookies = self.session.cookie_jar.filter_cookies(prev_domain)
        for cookie in cookies:
            cookie['domain'] = new_domain
        return cookies



async def main():

    async with aiohttp.ClientSession(headers={'User-Agent': const.USER_AGENT}) as session:

        loginSession = Login(session=session)

        await loginSession.login()
        await asyncio.sleep(5)
        await loginSession.logout()




if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
