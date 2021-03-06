import re
import time
import aiohttp
import asyncio
from yarl import URL
from bs4 import BeautifulSoup
from http.cookies import SimpleCookie

import rsa
import hmac
import base64
import hashlib

try:
    from tools.config import Const as const
    from tools.config import Config as cfg
except ImportError:
    raise Exception("Please, fill out the 'config_temp.py' file with the needed information, then rename it to just 'config.py'.")






class Login:

    def __init__(self, session):
        self.session = session
        self.logged_in = False
        self.bptf_logged_in = False
        self.steam_logged_in = False



    @classmethod
    def encode_password(self, password, rsa_modulus, rsa_exponent) -> str:
        return  base64.b64encode(rsa.encrypt(password.encode('UTF-8'), rsa.PublicKey(rsa_modulus, rsa_exponent))).decode("utf-8")




    @classmethod
    def gen_steam_guard_code(self, shared_secret: str) -> str:

        hash_ = hmac.digest(
            key=base64.b64decode(shared_secret),
            msg=(int(time.time()) // 30).to_bytes(8, byteorder='big'),
            digest=hashlib.sha1
            )

        b = hash_[19] & 0xF
        code_point = (hash_[b] & 0x7F) << 24 | (hash_[b + 1] & 0xFF) << 16 | (hash_[b + 2] & 0xFF) << 8 | (hash_[b + 3] & 0xFF)

        code = ''
        char_set = '23456789BCDFGHJKMNPQRTVWXY'
        for _ in range(5):
            code_point, i = divmod(code_point, len(char_set))
            code += char_set[i]

        return code




    @classmethod
    def jar_to_dict(self, cookie_jar) -> dict:
        return {cookie.key: cookie.value for cookie in cookie_jar}




    @classmethod
    def check_resp(self, status: int = 200, expected_status: int = 200, err_messsage: str = '') -> None:
        
        if status != expected_status or err_messsage:
            if err_messsage:
                raise Exception(err_messsage)  
            raise Exception(f'There was an error. Expected status: {expected_status}, actual status: {status}')




    def get_session(self) -> aiohttp.ClientSession:
        return self.session

    
    def is_logged_in(self) -> bool:
        return self.logged_in

    
    def is_bptf_logged_in(self) -> bool:
        return self.bptf_logged_in


    def is_steam_logged_in(self) -> bool:
        return self.steam_logged_in




    async def steam_login(self) -> None:

        resp = await self.session.post('https://steamcommunity.com/login/getrsakey/', data={'username': cfg.USERNAME})
        self.check_resp(resp.status)
        ourRsa = await resp.json()


        two_factor_code = self.gen_steam_guard_code(shared_secret=cfg.SHARED_SECRET)
        encoded_password = self.encode_password(
            password=cfg.PASSWORD,
            rsa_modulus=int(ourRsa['publickey_mod'], 16),
            rsa_exponent=int(ourRsa['publickey_exp'], 16)
            )

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
        self.check_resp(resp.status)
        resp = await resp.json()

        for url in resp['transfer_urls']:
            await self.session.post(url, data=resp['transfer_parameters'])
            

        
        cookies = self.session.cookie_jar.filter_cookies(const.COMMUNITY_URL[8:])
        for cookie in cookies:
            cookie['domain'] = const.STORE_URL[8:]

        self.session.cookie_jar.update_cookies(cookies, URL(const.COMMUNITY_URL))


        # check whether we are really logged in
        resp = await self.session.get('https://steamcommunity.com')
        self.check_resp(resp.status)
        resp = (await resp.read()).decode(encoding='utf-8', errors='ignore')

        try:
            steamID64, _, username = re.findall(r'<a href="https://steamcommunity.com/profiles/(.*?)/" data-miniprofile="(.*?)">(.*?)</a>', resp)[0]
        except (ValueError, IndexError):
            raise Exception('some exception')

        self.steam_logged_in = True
        print(f'Successfully logged in to steam as {username} ({steamID64}).')



    async def backpack_login(self) -> None:

        resp = await self.session.post('https://backpack.tf/login')
        self.check_resp(resp.status)
    
        soup = BeautifulSoup((await resp.read()).decode(encoding='utf-8', errors='ignore'), "lxml")
        payload = {field['name']: field['value'] for field in soup.find("form", id="openidForm").find_all('input') if 'name' in field.attrs}

        resp = await self.session.post('https://steamcommunity.com/openid/login', data=payload, allow_redirects=False)
        self.check_resp(resp.status, 302)
        resp = await self.session.get(resp.headers['Location'], allow_redirects=False)  # redirect 1
        self.check_resp(resp.status, 301)
        resp = await self.session.get(resp.headers['Location'], allow_redirects=False)  # redirect 2 --x--> redirect 3 (https://backpack.tf)
        self.check_resp(resp.status, 302)


        stack_cookies = SimpleCookie()
        for cookie in resp.headers.getall('Set-Cookie'):
            if 'Max-Age=0;' not in cookie:  # 2 empty, 2 valuable cookie pairs
                stack_cookies.load(cookie.replace('[', '%5B').replace(']', '%5D'))  # there's a problem with the [] in the cookie keys
        
        self.session.cookie_jar.update_cookies(stack_cookies)


        resp = await self.session.get('https://backpack.tf')
        self.check_resp(resp.status)
        resp = (await resp.read()).decode(encoding='utf-8', errors='ignore')
        resp = re.sub(r'[\t\n]', '', resp).replace('    ', '')

        
        try:
            steamID64, username = re.findall(r'<a href="/profiles/(.*?)">(.*?)</a>', resp)[0]
        except (ValueError, IndexError):
            raise Exception('some exception')
        
        self.bptf_logged_in = True
        print(f'Successfully logged in to backpack.tf as {username} ({steamID64}).')



    async def login(self) -> None:
        await self.steam_login()
        await self.backpack_login()

        if not (self.steam_logged_in and self.bptf_logged_in):
            check_resp(err_messsage='There was an error while logging in.')

        print('Successfully logged in.')
        self.logged_in = True



    async def steam_logout(self) -> None:

        cookies = self.jar_to_dict(self.session.cookie_jar)
        resp = await self.session.post('https://steamcommunity.com/login/logout/', data={'sessionid': cookies['sessionid']})
        self.check_resp(resp.status)

        self.steam_logged_in = False
        print('Successfully logged out from steam.')




    async def backpack_logout(self) -> None:

        cookies = self.jar_to_dict(self.session.cookie_jar)
        resp = await self.session.get(f"https://backpack.tf/logout?user-id={cookies['user-id']}")
        self.check_resp(resp.status)

        self.bptf_logged_in = False
        print('Successfully logged out from backpack.tf.')




    async def logout(self) -> None:
        await self.steam_logout()
        await self.backpack_logout()
        
        if self.steam_logged_in or self.bptf_logged_in:
            self.check_resp(err_messsage='There was an error while logging out.')

        await asyncio.sleep(0.1)
        await self.session.close()
        
        self.logged_in = False
        print('Successfully logged out.')






async def main():

    async with aiohttp.ClientSession(headers={'User-Agent': const.USER_AGENT}) as session:

        loginSession = Login(session=session)

        await loginSession.login()
        await asyncio.sleep(5)
        await loginSession.logout()




if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
