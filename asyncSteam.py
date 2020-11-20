import re
import time
import json
import aiohttp
import asyncio
from bs4 import BeautifulSoup


import tools.utils as utils
import tools.steam_utils as stm_utils

from tools.config import Const as const
from tools.config import Config as cfg






async def json_or_text(r: aiohttp.ClientResponse):
    text = await r.text()
    try:
        if "application/json" in r.headers["Content-Type"]:
            return json.loads(text)
    except KeyError:
        pass
    return text




class SteamLogin:
    
    def __init__(self, session):
        self.session = session


        self.username = None
        self.password = None
        self.api_key = None
        self.shared_secret = None
        self.steam_guard_code = ""
        self.email_auth = ""
        self.captcha_id = "-1"
        self.captcha_text = ""
        self.steam_id = ""

        self.session_id = None
        self.user = None
        self.logged_in = False






    def get_session(self):
        return self.session

    

    async def request(self, method, url, **kwargs):
        kwargs["headers"] = {"User-Agent": const.USER_AGENT, **kwargs.get("headers", {})}
        payload = kwargs.get("data")
        
        async with self.session.request(method, url, **kwargs) as r:
            return await json_or_text(r), r.status
            




    async def do_login(self):
        password, timestamp = await self.get_rsa_params()
        payload = {
            "username": self.username,
            "password": password,
            "emailauth": self.email_auth,
            "emailsteamid": self.steam_id,
            "twofactorcode": self.steam_guard_code,
            "captchagid": self.captcha_id,
            "captcha_text": self.captcha_text,
            "loginfriendlyname": const.USER_AGENT,
            "rsatimestamp": timestamp,
            "remember_login": True,
            "donotcache": int(time.time() * 1000),
        }

        try:
            resp, status = await self.request("POST", f'{const.COMMUNITY_URL}/login/dologin', data=payload)
            if resp.get("requires_twofactor"):
                self.steam_guard_code = stm_utils.gen_steam_guard_code(self.shared_secret)
            elif resp.get("emailauth_needed"):
                self.steam_id = resp.get("emailsteamid")
                self.email_auth = await stm_utils.gen_steam_guard_code(self.shared_secret)
            else:
                return resp
            return await self.do_login()
        except Exception as exc:
            # raise errors.LoginError from exc
            raise RuntimeError("Steam login error") from exc




    async def get_rsa_params(self):
        payload = {"username": self.username, "donotcache": int(time.time() * 1000)}
        
        try:
            resp, status = await self.request("POST", f'{const.COMMUNITY_URL}/login/getrsakey', data=payload)
        except Exception as exc:
            raise RuntimeError('Failed to get RSA key') from exc
        
        try:
            rsa_timestamp = resp["timestamp"]
            encoded_password = stm_utils.encode_password(
                as_string=True,
                password=cfg.PASSWORD, 
                rsa_modulus=int(resp['publickey_mod'], 16),
                rsa_exponent=int(resp['publickey_exp'], 16)
            )

        except KeyError:
            raise RuntimeError('Could not obtain rsa-key')
        else:
            return encoded_password, rsa_timestamp




    async def login(self, username: str, password: str, shared_secret):
        self.username = username
        self.password = password
        self.shared_secret = shared_secret

        

        resp = await self.do_login()

        if resp.get("captcha_needed") and resp.get("message") != "Please wait and try again later.":
            self._captcha_id = resp["captcha_gid"]
            print(f"Please enter the captcha text at https://steamcommunity.com/login/rendercaptcha/?gid={resp['captcha_gid']}")
            
            return

            '''
            captcha_text = await utils.ainput(">>> ")
            self._captcha_text = captcha_text.strip()
            return await self.login(username, password, shared_secret)
            '''

        if not resp["success"]:
            # raise errors.InvalidCredentials(resp.get("message", "An unexpected error occurred"))
            raise RuntimeError(resp.get("message", "An unexpected error occurred"))

        data = resp.get("transfer_parameters")
        if data is None:
            #raise errors.LoginError("Cannot perform redirects after login. Steam is likely down, please try again later.")
            raise RuntimeError("Cannot perform redirects after login. Steam is likely down, please try again later.")

        for url in resp["transfer_urls"]:
            await self.request("POST", url=url, data=data)

        '''
        self.api_key = self._client.api_key = await self.get_api_key()
        if self.api_key is None:
            log.info("Failed to get API key")
            BaseUser._patch_without_api()
            utils.warn("Some methods of User objects are not available as no API key can be generated", UserWarning)
            await self.request("GET", community_route("home"))
        '''

        cookies = self.session.cookie_jar.filter_cookies(const.COMMUNITY_URL)
        print(utils.jar_to_dict(self.session.cookie_jar))
        self.session_id = utils.jar_to_dict(self.session.cookie_jar)['sessionid']

        '''
        resp = await self.get_user(resp["transfer_parameters"]["steamid"])
        data = resp["response"]["players"][0]
        state = self._client._connection
        self.user = ClientUser(state=state, data=data)
        state._users[self.user.id64] = self.user
        self.logged_in = True
        self._client.dispatch("login")
        '''

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





        
        resp = await self.session.post('https://backpack.tf/login')
        if resp.status != 200:
            raise Exception(f"There was an error while logging into backpack.tf.\n   Reason: {resp.status}")
        
        req_url = resp.url
        resp = await resp.read()

        soup = BeautifulSoup(resp.decode(encoding='utf-8', errors='ignore'), "lxml")
        payload = {
            'action': str(soup.findAll("input", {"name": "action"})[0]['value']),
            'openidmode': str(soup.findAll("input", {"name": "openid.mode"})[0]['value']),
            'openidparams': str(soup.findAll("input", {"name": "openidparams"})[0]['value']),
            'nonce': str(soup.findAll("input", {"name": "nonce"})[0]['value'])
            }

        resp = await self.session.post(req_url, json=payload)
        if resp.status != 200:
            raise Exception(f"There was an error while logging into backpack.tf.\n   Reason: {resp.status}")


        # check whether we are really logged in
        resp = await self.session.get("https://backpack.tf/")
        resp = await resp.read()
        print(resp)
        resp = re.sub(r'[\r\n\t]', '', resp.decode(encoding='utf-8', errors='ignore')).replace('  ', '')

        login_data = re.findall(r'<a href="/profiles/(.*?)">(.*?)</a>', resp)

        if login_data:
            steamID64, username = login_data[0]
            print(f"Successfully logged in to backpack.tf as {username} ({steamID64}).")
        else:
            raise Exception("There was an error while logging into backpack.tf.\n   Reason: unknown")






    async def logout(self):
        payload = {"sessionid": self.session_id}
        await self.request("POST", f'{const.COMMUNITY_URL}/login/logout', data=payload)






async def main():

    async with aiohttp.ClientSession(headers={'User-Agent': const.USER_AGENT}) as session:

        loginSession = SteamLogin(session=session)

        await loginSession.login(username=cfg.USERNAME, password=cfg.PASSWORD, shared_secret=cfg.SHARED_SECRET)
        await asyncio.sleep(5)
        await loginSession.logout()




if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())

