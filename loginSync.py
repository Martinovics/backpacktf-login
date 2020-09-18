import time
import requests
from bs4 import BeautifulSoup

import tools.utils as utils
import tools.steam_guard as steam_guard
from tools.config import Const as const
from tools.config import Config as cfg




class Login:
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': const.USER_AGENT})
        self.logged_in_to_steam = False
        self.logged_in_to_backpack = False




    def get_session(self):
        return self.session




    def steam_login(self) -> None:
        if self.logged_in_to_steam:
            print("You are already logged in to steam.")
            return


        ourRsa = self.session.post('https://steamcommunity.com/login/getrsakey/', data={'username': cfg.USERNAME}).json()

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

        resp = self.session.post("https://store.steampowered.com/login/dologin", data=payload).json()

        if not resp['success']:
            err = 'There was an error while logging into steam.'
            if resp.get('message'):
                err += f"\n   Reason: {resp['message']}"
            raise Exception(err)

        for url in resp['transfer_urls']:
            self.session.post(url, data=resp['transfer_parameters'])


        stm_cookies = self.session.cookies.get_dict()
        self.session.cookies.set(**{"name": "sessionid", "value": stm_cookies['sessionid'], "domain": 'steamcommunity.com'})
        self.session.cookies.set(**{"name": "sessionid", "value": stm_cookies['sessionid'], "domain": 'store.steampowered.com'})

        self.logged_in_to_steam = True
        print('Successfully logged in to steam.')




    def backpack_login(self) -> None:
        if self.logged_in_to_backpack:
            print("You are already logged in to backpack.tf.")
            return
        
        
        resp = self.session.post('https://backpack.tf/login')
        if resp.status_code != 200:
            raise Exception(f"There was an error while logging into backpack.tf.\n   Reason: {resp.status_code}")

        soup = BeautifulSoup(resp.text, "lxml")  # .read() --> .decode(encoding='utf-8', errors='ignore')
        payload = {
            'action': soup.findAll("input", {"name": "action"})[0]['value'],
            'openidmode': soup.findAll("input", {"name": "openid.mode"})[0]['value'],
            'openidparams': soup.findAll("input", {"name": "openidparams"})[0]['value'],
            'nonce': soup.findAll("input", {"name": "nonce"})[0]['value']
            }

        resp = self.session.post(resp.url, data=payload)
        if resp.status_code != 200:
            raise Exception(f"There was an error while logging into backpack.tf.\n   Reason: {resp.status_code}")

        self.logged_in_to_backpack = True
        print('Successfully logged in to backpack.tf.')




    def login(self) -> None:
        self.steam_login()
        self.backpack_login()
        print('Successfully logged in.')




    def steam_logout(self) -> None:
        if not self.logged_in_to_steam:
            print("You aren't logged in to steam.")
            return
        
        self.session.post('https://steamcommunity.com/login/logout/', data={'sessionid': self.session.cookies.get_dict()['sessionid']})
        self.logged_in_to_steam = False
        print('Successfully logged out from steam.')




    def backpack_logout(self) -> None:
        if not self.logged_in_to_backpack:
            print("You aren't logged in to backpack.tf.")
            return

        self.session.get(f"https://backpack.tf/logout?user-id={self.session.cookies.get_dict()['user-id']}")
        self.logged_in_to_backpack = False
        print('Successfully logged out from backpack.tf.')




    def logout(self) -> None:
        self.steam_logout()
        self.backpack_logout()
        
        self.session.close()
        print('Successfully logged out.')






if __name__ == '__main__':
    loginSession = Login()

    loginSession.login()

    resp = loginSession.get_session().get("https://backpack.tf/")
    print(resp.text)

    time.sleep(5)
    loginSession.logout()
