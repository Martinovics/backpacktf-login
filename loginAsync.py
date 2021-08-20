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

from tools.Config import Config as cfg
from tools.Config import Const as const






class Login:


    API_URL = 'https://api.steampowered.com'
    STORE_URL = 'https://store.steampowered.com'
    COMMUNITY_URL = 'https://steamcommunity.com'


    def __init__(self, username: str, password: str, shared_secret: str):

        self.session = aiohttp.ClientSession(headers={'User-Agent': const.USER_AGENT})

        self.username = username
        self.password = password
        self.shared_secret = shared_secret

        self.steam_logged_in = False
        self.backpack_logged_in = False
        self.marketplace_logged_in = False

        self.steam_logout_auth = ''
        self.backpack_logout_url = ''




    def get_session(self) -> aiohttp.ClientSession:
        return self.session




    async def close_session(self) -> None:
        await self.session.close()




    async def _send_request(self, method: str, url: str, data={}, allow_redirects=True,
                            expected_status: int = 200, return_as: str = ''):

        method = method.lower()
        timeout = aiohttp.ClientTimeout(total=20)

        try:
            if method == 'get':
                resp = await self.session.get(url=url, allow_redirects=allow_redirects, timeout=timeout)
            elif method == 'post':
                resp = await self.session.post(url=url, data=data, allow_redirects=allow_redirects, timeout=timeout)
            else:
                return
        except asyncio.TimeoutError:
            return


        if resp and resp.status == expected_status:

            if return_as == 'text':
                return (await resp.read()).decode(encoding='utf-8', errors='ignore')
            elif return_as == 'json':
                return (await resp.json())
            else:
                return resp

        else:
            if resp:
                print(f'({resp.status}) request failed {url}')
            else:
                print(f'request failed {url}')

            return




    @classmethod
    def jar_to_dict(self, cookie_jar) -> dict:
        return {cookie.key: cookie.value for cookie in cookie_jar}




    # steam functions -===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-=


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




    # steam functions -==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-=


    async def steam_login(self) -> bool:

        # get rsa stuff ------------------------------------------------------------------------------------------------

        resp = await self._send_request(
            'post', url='https://steamcommunity.com/login/getrsakey', data={'username': self.username}, return_as='json'
        )

        if not resp:
            return False


        # do login -----------------------------------------------------------------------------------------------------

        two_factor_code = self.gen_steam_guard_code(shared_secret=self.shared_secret)
        encoded_password = self.encode_password(
            password=self.password,
            rsa_modulus=int(resp['publickey_mod'], 16),
            rsa_exponent=int(resp['publickey_exp'], 16)
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
            'rsatimestamp': resp['timestamp'],
            'donotcache': str(int(time.time() * 1000))
        }

        resp = await self._send_request(
            'post', url='https://store.steampowered.com/login/dologin', data=payload, return_as='json'
        )

        if not resp:
            return False


        # --------------------------------------------------------------------------------------------------------------

        self.steam_logout_auth = resp['transfer_parameters']['auth']


        # transfer params, set cookies ---------------------------------------------------------------------------------

        for url in resp['transfer_urls']:

            if not (await self._send_request(method='post', url=url, data=resp['transfer_parameters'])):
                return False


        cookies = self.session.cookie_jar.filter_cookies(Login.COMMUNITY_URL[8:])
        for cookie in cookies:
            cookie['domain'] = Login.STORE_URL[8:]

        self.session.cookie_jar.update_cookies(cookies, URL(Login.COMMUNITY_URL))

        return True




    async def steam_logout(self) -> bool:  # NOTE: does not work

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

        return True




    async def is_steam_logged_in(self, check_with_request: bool = False) -> bool:

        if check_with_request:

            resp = await self._send_request(method='get', url='https://steamcommunity.com', return_as='text')

            if not resp:
                self.steam_logged_in = False
                return False

            if 'data-miniprofile' in resp:
                self.steam_logged_in = True
                return True
            else:
                self.steam_logged_in = False
                return False

        return self.steam_logged_in




    # backpack.tf functions -===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===


    async def backpack_login(self) -> None:

        # get login information ----------------------------------------------------------------------------------------

        resp = await self._send_request(method='post', url='https://backpack.tf/login', return_as='text')

        if not resp:
            return False


        # do login -----------------------------------------------------------------------------------------------------

        soup = BeautifulSoup(resp, "lxml")
        inputs = soup.find("form", id="openidForm").find_all('input')
        payload = {field['name']: field['value'] for field in inputs if 'name' in field.attrs}

        resp = await self._send_request(
            method='post',
            url='https://steamcommunity.com/openid/login',
            data=payload,
            allow_redirects=False,
            expected_status=302
        )

        if not resp:
            return False

        resp = await self._send_request(
            method='get',
            url=resp.headers['Location'],
            allow_redirects=False,
            expected_status=301
        )

        if not resp:
            return False

        resp = await self._send_request(
            method='get',
            url=resp.headers['Location'],
            allow_redirects=False,
            expected_status=302
        )

        if not resp:
            return False


        stack_cookies = SimpleCookie()
        for cookie in resp.headers.getall('Set-Cookie'):
            if 'Max-Age=0;' not in cookie:  # 2 empty, 2 not-empty cookies
                stack_cookies.load(cookie.replace('[', '%5B').replace(']', '%5D'))
                # there's a problem with the [] in the cookie keys

        self.session.cookie_jar.update_cookies(stack_cookies)


        # set logout url -----------------------------------------------------------------------------------------------
        resp = await self._send_request(method='get', url='https://backpack.tf', return_as='text')

        if not resp:
            return False


        try:
            user_id = re.findall(r"<a href='/logout\?user-id=(.*?)'>", resp)[0]
            self.backpack_logout_url = f"https://backpack.tf/logout?user-id={user_id}"
        except (ValueError, IndexError):
            return False


        return True




    async def backpack_logout(self) -> bool:
        await self._send_request(method='get', url=self.backpack_logout_url)
        return True




    async def is_backpack_logged_in(self, check_with_request: bool = False) -> bool:

        if check_with_request:

            resp = await self._send_request(method='get', url='https://backpack.tf', return_as='text')

            if not resp:
                self.backpack_logged_in = False
                return False

            if '<div class="username">' in resp:
                self.backpack_logged_in = True
                return True
            else:
                self.backpack_logged_in = False
                return False

        return self.backpack_logged_in




    # marketplace.tf functions -===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-===-


    async def marketplace_login(self) -> bool:
        resp = await self._send_request(method='get', url='https://marketplace.tf/login')

        if not resp:
            return False


        soup = BeautifulSoup((await resp.read()).decode(encoding='utf-8', errors='ignore'), "lxml")

        input_fields = soup.find("form", id="openidForm").find_all('input')
        payload = {field['name']: field['value'] for field in input_fields if 'name' in field.attrs}

        await self._send_request(method='post', url='https://steamcommunity.com/openid/login', data=payload)




    async def marketplace_logout(self) -> bool:
        await self._send_request(method='get', url='https://marketplace.tf/?logout=1')
        return True




    async def is_marketplace_logged_in(self, check_with_request: bool = False) -> bool:
        if check_with_request:

            resp = await self._send_request('get', 'https://marketplace.tf/dashboard?override=true', return_as='text')

            if not resp:
                self.marketplace_logged_in = False
                return False

            if 'LoggedIn: true,' in resp:
                self.marketplace_logged_in = True
                return True
            else:
                self.marketplace_logged_in = False
                return False

        return self.marketplace_logged_in




    async def is_logged_in(self, check_with_request: bool = False) -> bool:
        return \
            await self.is_steam_logged_in(check_with_request=check_with_request) and \
            await self.is_backpack_logged_in(check_with_request=check_with_request) and \
            await self.is_marketplace_logged_in(check_with_request=check_with_request)




    async def login(self) -> bool:


        await self.steam_login()
        if not (await self.is_steam_logged_in(check_with_request=True)):
            return False

        await self.backpack_login()
        if not (await self.is_backpack_logged_in(check_with_request=True)):
            return False

        await self.marketplace_login()
        if not (await self.is_marketplace_logged_in(check_with_request=True)):
            return False


        return True




    async def logout(self) -> bool:


        await self.marketplace_logout()
        if (await self.is_marketplace_logged_in(check_with_request=True)):
            return False

        await self.backpack_logout()
        if (await self.is_backpack_logged_in(check_with_request=True)):
            return False

        '''
        await self.steam_logout()
        if (await self.is_steam_logged_in(check_with_request=True)):
            return False
        '''


        return True






async def main():


    loginSession = Login(
        username=cfg.USERNAME,
        password=cfg.PASSWORD,
        shared_secret=cfg.SHARED_SECRET
    )


    if (await loginSession.login()):
        print('Logged in.')

    await asyncio.sleep(5)  # do something

    if (await loginSession.logout()):
        print('Logged out.')


    await loginSession.close_session()






if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
