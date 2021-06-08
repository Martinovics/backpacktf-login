import re
import time
# import json
import aiohttp
import asyncio
# import aiofiles
from yarl import URL
from bs4 import BeautifulSoup
from http.cookies import SimpleCookie

import rsa
import hmac
import base64
import hashlib

from tools.Config import Const as const
from tools.Config import Config as cfg






class Login:

    REQUEST_RETRY: int = 2  # retry request this many times

    API_URL = 'https://api.steampowered.com'
    STORE_URL = 'https://store.steampowered.com'
    COMMUNITY_URL = 'https://steamcommunity.com'

    def __init__(self, session, username: str, password: str, shared_secret: str):
        self.session = session  # you need an external session
        self.username = username
        self.password = password
        self.shared_secret = shared_secret

        self.logged_in = False
        self.steam_logged_in = False
        self.backpack_logged_in = False
        self.marketplace_logged_in = False
        self.retries = 0

        self.steam_logout_auth = ''
        self.backpack_logout_url = ''




    @classmethod
    def jar_to_dict(self, cookie_jar) -> dict:
        return {cookie.key: cookie.value for cookie in cookie_jar}




    @classmethod
    def elapsed_time(self, seconds: [int, float]) -> str:
        seconds = int(seconds)

        hour = seconds // 3600
        minute = (seconds - hour * 3600) // 60
        second = seconds - hour * 3600 - minute * 60

        return f'{hour}h{minute}m{second}s'




    @classmethod
    def join_url_and_params(self, url, params):

        if url.endswith('/'):
            url = url[:-1]

        if not params:
            return url

        url += '?'

        for key, value in params.items():
            url += f'{key}={value}&'

        if url.endswith('&'):
            url = url[:-1]

        return url




    async def close_session(self) -> None:
        await self.session.close()




    async def _send_request(self, method: str, url: str, data={}, allow_redirects=True, expected_status: int = 200):

        method = method.lower()
        if method not in ['get', 'post']:
            method = 'get'


        timeout = aiohttp.ClientTimeout(total=20)
        try:
            if method == 'get':
                resp = await self.session.get(url=url, allow_redirects=allow_redirects, timeout=timeout)
            else:
                resp = await self.session.post(url=url, data=data, allow_redirects=allow_redirects, timeout=timeout)
        except asyncio.TimeoutError:
            resp = None


        if not resp or (resp.status != expected_status):
            if self.retries < Login.REQUEST_RETRY:
                retry_in = 10 if resp.status != 429 else 120

                if resp:
                    print(str((await resp.json())))
                else:
                    print(f'Request failed. Retrying in {retry_in} seconds.')

                self.retries += 1
                await asyncio.sleep(retry_in)
                resp = await self._send_request(method, url, data, allow_redirects, expected_status)
            else:
                self.retries = 0
                await self.close_session()
                raise Exception(f'Unexpected status from {url}')  # TODO this isn't that good
        else:
            self.retries = 0

        return resp




    @classmethod
    def encode_password(self, password, rsa_modulus, rsa_exponent) -> str:
        password = password.encode('UTF-8')
        public_key = rsa.PublicKey(rsa_modulus, rsa_exponent)
        return base64.b64encode(rsa.encrypt(password, public_key)).decode("utf-8")




    @classmethod
    def gen_steam_guard_code(self, shared_secret: str) -> str:

        hash_ = hmac.digest(
            key=base64.b64decode(shared_secret),
            msg=(int(time.time()) // 30).to_bytes(8, byteorder='big'),
            digest=hashlib.sha1
        )

        b = hash_[19] & 0xF
        code_point = (hash_[b] & 0x7F) << 24 | \
                     (hash_[b + 1] & 0xFF) << 16 | \
                     (hash_[b + 2] & 0xFF) << 8 | \
                     (hash_[b + 3] & 0xFF)

        code = ''
        char_set = '23456789BCDFGHJKMNPQRTVWXY'
        for _ in range(5):
            code_point, i = divmod(code_point, len(char_set))
            code += char_set[i]

        return code




    async def steam_login(self) -> None:

        resp = await self._send_request(method='post', url='https://steamcommunity.com/login/getrsakey/',
                                        data={'username': self.username})
        ourRsa = await resp.json()


        two_factor_code = self.gen_steam_guard_code(shared_secret=self.shared_secret)
        encoded_password = self.encode_password(
            password=self.password,
            rsa_modulus=int(ourRsa['publickey_mod'], 16),
            rsa_exponent=int(ourRsa['publickey_exp'], 16)
        )

        payload = {
            'username': self.username,
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


        resp = await self._send_request(method='post', url='https://store.steampowered.com/login/dologin', data=payload)
        resp = await resp.json()

        self.steam_logout_auth = resp['transfer_parameters']['auth']

        for url in resp['transfer_urls']:
            await self._send_request(method='post', url=url, data=resp['transfer_parameters'])


        cookies = self.session.cookie_jar.filter_cookies(Login.COMMUNITY_URL[8:])
        for cookie in cookies:
            cookie['domain'] = Login.STORE_URL[8:]

        self.session.cookie_jar.update_cookies(cookies, URL(Login.COMMUNITY_URL))


        if (await self.is_steam_logged_in(check_with_request=True)):
            self.steam_logged_in = True
            print('Logged in to steam.')
        else:
            self.steam_logged_in = False
            print('Could not log in to steam.')




    async def steam_logout(self) -> None:  # does not work

        '''
        self._send_request(
            method='post',
            url='https://steamcommunity.com/login/logout/',
            data={'sessionid': self.jar_to_dict(self.session.cookie_jar)['sessionid']}
        )

        payload = {'in_transfer': 1, 'auth': self.steam_logout_auth}
        await self._send_request(method='post', url='https://store.steampowered.com/login/logout/', data=payload)
        await self._send_request(method='post', url='https://help.steampowered.com/login/logout/', data=payload)


        if not (await self.is_steam_logged_in(check_with_request=True)):
            self.steam_logged_in = False
            print('Logged out from steam.')
        else:
            self.steam_logged_in = True
            print('Could not log out from steam.')
        '''


        self.steam_logged_in = False
        print('Logged out from steam.')





    async def is_steam_logged_in(self, check_with_request: bool = False) -> bool:

        if check_with_request:

            resp = await self._send_request('get', 'https://steamcommunity.com')
            resp = (await resp.read()).decode(encoding='utf-8', errors='ignore')

            if 'data-miniprofile' in resp:
                return True
            else:
                return False

        return self.steam_logged_in




    async def backpack_login(self) -> None:

        resp = await self._send_request(method='post', url='https://backpack.tf/login')

        soup = BeautifulSoup((await resp.read()).decode(encoding='utf-8', errors='ignore'), "lxml")
        inputs = soup.find("form", id="openidForm").find_all('input')
        payload = {field['name']: field['value'] for field in inputs if 'name' in field.attrs}

        resp = await self._send_request(method='post', url='https://steamcommunity.com/openid/login', data=payload,
                                        allow_redirects=False, expected_status=302)
        resp = await self._send_request(method='get', url=resp.headers['Location'],
                                        allow_redirects=False, expected_status=301)
        resp = await self._send_request(method='get', url=resp.headers['Location'],
                                        allow_redirects=False, expected_status=302)


        stack_cookies = SimpleCookie()
        for cookie in resp.headers.getall('Set-Cookie'):
            if 'Max-Age=0;' not in cookie:  # 2 empty, 2 not-empty cookies
                stack_cookies.load(cookie.replace('[', '%5B').replace(']', '%5D'))
                # there's a problem with the [] in the cookie keys

        self.session.cookie_jar.update_cookies(stack_cookies)


        # set logout url
        resp = await self.session.get('https://backpack.tf')
        resp = (await resp.read()).decode(encoding='utf-8', errors='ignore')

        try:
            user_id = re.findall(r"<a href='/logout\?user-id=(.*?)'>", resp)[0]
            self.backpack_logout_url = f"https://backpack.tf/logout?user-id={user_id}"
        except (ValueError, IndexError):
            pass


        if (await self.is_backpack_logged_in(check_with_request=True)):
            self.backpack_logged_in = True
            print('Logged in to backpack.tf.')
        else:
            self.backpack_logged_in = False
            print('Could not log in to backpack.tf.')




    async def backpack_logout(self) -> None:
        await self._send_request(method='get', url=self.backpack_logout_url)


        if not (await self.is_backpack_logged_in(check_with_request=True)):
            self.backpack_logged_in = False
            print('Logged out from backpack.tf.')
        else:
            self.backpack_logged_in = True
            print('Could not log out from backpack.tf.')




    async def is_backpack_logged_in(self, check_with_request: bool = False) -> bool:

        if check_with_request:

            resp = await self._send_request('get', 'https://backpack.tf')
            resp = (await resp.read()).decode(encoding='utf-8', errors='ignore')

            if '<div class="username">' in resp:
                return True
            else:
                return False

        return self.backpack_logged_in




    async def marketplace_login(self) -> None:
        resp = await self._send_request(method='get', url='https://marketplace.tf/login')

        soup = BeautifulSoup((await resp.read()).decode(encoding='utf-8', errors='ignore'), "lxml")

        input_fields = soup.find("form", id="openidForm").find_all('input')
        payload = {field['name']: field['value'] for field in input_fields if 'name' in field.attrs}

        await self._send_request(method='post', url='https://steamcommunity.com/openid/login', data=payload)


        if (await self.is_marketplace_logged_in(check_with_request=True)):
            self.marketplace_logged_in = True
            print('Logged in to marketplace.tf.')
        else:
            self.marketplace_logged_in = False
            print('Could not log in to marketplace.tf.')




    async def marketplace_logout(self) -> None:
        await self._send_request(method='get', url='https://marketplace.tf/?logout=1')


        if not (await self.is_marketplace_logged_in(check_with_request=True)):
            self.marketplace_logged_in = False
            print('Logged out from marketplace.tf.')
        else:
            self.marketplace_logged_in = True
            print('Could not log out from marketplace.tf.')




    async def is_marketplace_logged_in(self, check_with_request: bool = False) -> bool:
        if check_with_request:

            resp = await self._send_request('get', 'https://marketplace.tf/dashboard?override=true')
            resp = (await resp.read()).decode(encoding='utf-8', errors='ignore')

            if 'LoggedIn: true,' in resp:
                return True
            else:
                return False

        return self.marketplace_logged_in




    async def login(self) -> None:
        await self.steam_login()
        await self.backpack_login()
        await self.marketplace_login()




    async def relogin(self) -> None:
        await self.marketplace_logout()
        await self.backpack_logout()
        await self.steam_logout()

        await asyncio.sleep(3)

        await self.steam_login()
        await self.backpack_login()
        await self.marketplace_login()




    async def logout(self) -> None:
        await self.marketplace_logout()
        await self.backpack_logout()
        await self.steam_logout()

        await asyncio.sleep(0.2)
        await self.session.close()






async def main():

    async with aiohttp.ClientSession(headers={'User-Agent': const.USER_AGENT}) as session:

        loginSession = Login(
            session=session,
            username=cfg.USERNAME,
            password=cfg.PASSWORD,
            shared_secret=cfg.SHARED_SECRET
        )


        await loginSession.login()
        await asyncio.sleep(5)
        await loginSession.relogin()
        await asyncio.sleep(5)
        await loginSession.logout()




if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
