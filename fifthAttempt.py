import asyncio
import aiohttp

from tools.config import Config as cfg
from tools.config import Const as const

import base64
import time
import rsa
import requests
from tools.steam_guard import generate_code
from bs4 import BeautifulSoup

from yarl import URL
from tools.steam_enums import SteamUrls


class Login(object):
    def __init__(self, username, password, shared_secret, session):
        self.session = session


    def rsa_params(self, username):
        
        print(self.session)

        self.rsa_modulus = self.resp.get('rsa_mod')
        self.rsa_exponent = self.resp.get('rsa_exp')
        self.rsa_timestamp = self.resp.get('rsa_timestamp')
        self.rsa_publickey = rsa.PublicKey(self.rsa_modulus, self.rsa_exponent)
        self.encrypted_password = base64.b64encode(rsa.encrypt(cfg.PASSWORD.encode('UTF-8'), self.rsa_publickey))

        self.session.post("https://store.steampowered.com" + "/login/getrsakey/", data={
            "username": str(username),
        })
        return dict({'rsa_mod': int(self.resp['publickey_mod'], 16),
                     'rsa_exp': int(self.resp['publickey_exp'], 16),
                     'rsa_timestamp': int(self.resp['timestamp']),
                     })

    async def loginRequest(self, username, encrypted_password, shared_secret):
        loginForm = dict({
            "password": encrypted_password,
            "username": str(username),
            "twofactorcode": generate_code(shared_secret=str(shared_secret)),
            "emailauth": "",
            "loginfriendlyname": "",
            "captchagid": "-1",
            "captcha_text": "",
            "emailsteamid": "",
            "rsatimestamp": str(self.rsa_params(str(username)).get('rsa_timestamp')),
            "remember_login": "false",
            "donotcache": str(int(time.time()) * 1000)
        })
        login_request = await self.session.post("https://store.steampowered.com" + "/login/dologin", data=loginForm)
        loginreq_dict = await login_request.json()
        transfer_parameters = loginreq_dict.get('transfer_parameters')
        if transfer_parameters is None:
            print(loginForm['password'])
            raise Exception(loginreq_dict.get('message'))
        for url in loginreq_dict['transfer_urls']:
            await self.session.post(url, data=transfer_parameters)
        
        community_domain = SteamUrls.Community.value[8:]
        store_domain = SteamUrls.Store.value[8:]
        new_cookies = self._copy_cookies(store_domain, community_domain)
        self.session.cookie_jar.update_cookies(new_cookies, URL(SteamUrls.Community.value))
        
        return self.session
    
    def _copy_cookies(self, prev_domain, new_domain):
        prev_cookies = self.session.cookie_jar.filter_cookies(prev_domain)
        for cookie in prev_cookies:
            cookie['domain'] = new_domain
        return prev_cookies

    

    async def start_backpack_session(self):
        self.resp = await self.session.post("https://store.steampowered.com" + "/login/getrsakey/", data={
            "username": str(cfg.USERNAME),
        })
        self.resp = await self.resp.json()

        self.rsa_params(cfg.USERNAME)


        self.loginSession = await self.loginRequest(str(cfg.USERNAME), self.encrypted_password, str(cfg.SHARED_SECRET))
        
        
        
        
        self.openid_response = await self.loginSession.post("https://backpack.tf/login")
        self.response_html = await self.openid_response.decode(encoding='utf-8', errors='ignore')
        self.parameters = self.returnParameters(self.response_html)
        self.auth_resp = await self.loginSession.post(self.openid_response.url, data=self.parameters)


        resp = await self.session.get("https://backpack.tf/")
        resp = await resp.read()
        
        if cfg.USERNAME.lower() in resp.decode(encoding='utf-8', errors='ignore').lower():
            print("bptf ok")
        else:
            print("fail")

    @staticmethod
    def returnParameters(html):
        soup = BeautifulSoup(html, "lxml")
        action = soup.findAll("input", {"name": "action"})[0]['value']  # Or "steam_openid_login" in most of the cases
        mode = soup.findAll("input", {"name": "openid.mode"})[0]['value']  # Or "checkid_setup" in most of the cases
        openidparams = soup.findAll("input", {"name": "openidparams"})[0]['value']
        nonce = soup.findAll("input", {"name": "nonce"})[0]['value']
        return {
            "action": action,
            "openid.mode": mode,
            "openidparams": openidparams,
            "nonce": nonce
        }
    
    async def do_login(self):
        await self.start_backpack_session()


async def main():
    
    


    async with aiohttp.ClientSession(headers={'User-Agent': const.USER_AGENT}) as session:

        loginSession = Login(
            username=cfg.USERNAME, password=cfg.PASSWORD, shared_secret=cfg.SHARED_SECRET,
            session=aiohttp.ClientSession(headers={'User-Agent': const.USER_AGENT})
            )
        await loginSession.do_login()
        await asyncio.sleep(5)
        


    '''
    async with aiohttp.ClientSession(headers={'User-Agent': const.USER_AGENT}) as session:

        resp = await session.post('https://backpack.tf/login')
        print(resp.status)

        resp = await session.get(resp.url)
        print(resp.status)
        print(resp.text)
    '''










if __name__  == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
