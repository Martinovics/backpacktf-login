import rsa
import time
import base64
import requests
from bs4 import BeautifulSoup

import tools.steam_guard as steam_guard
from tools.config import Config as cfg

# TODO: error handling


class Login:
    
    def __init__(self):
        self.session = requests.Session()




    def get_session(self):
        return self.session




    def steam_login(self) -> None:
        ourRsa = self.session.post('https://steamcommunity.com/login/getrsakey/', data={'username': cfg.USERNAME}).json()

        publickey = rsa.PublicKey(int(ourRsa['publickey_mod'], 16), int(ourRsa['publickey_exp'], 16))
        encoded_password = base64.b64encode(rsa.encrypt(cfg.PASSWORD.encode('UTF-8'), publickey))

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
            if resp['message']:
                err += f"\n   Reason: {resp['message']}"
            raise Exception(err)

        for url in resp['transfer_urls']:
            self.session.post(url, resp['transfer_parameters'])


        stm_cookies = self.session.cookies.get_dict()
        self.session.cookies.set(**{"name": "sessionid", "value": stm_cookies['sessionid'], "domain": 'steamcommunity.com'})
        self.session.cookies.set(**{"name": "sessionid", "value": stm_cookies['sessionid'], "domain": 'store.steampowered.com'})




    def backpack_login(self) -> None:
        resp = self.session.post('https://backpack.tf/login')

        soup = BeautifulSoup(resp.text, "lxml")  # .read() --> .decode(encoding='utf-8', errors='ignore')
        payload = {
            'action': soup.findAll("input", {"name": "action"})[0]['value'],
            'openidmode': soup.findAll("input", {"name": "openid.mode"})[0]['value'],
            'openidparams': soup.findAll("input", {"name": "openidparams"})[0]['value'],
            'nonce': soup.findAll("input", {"name": "nonce"})[0]['value']
            }

        self.session.post(resp.url, data=payload)




    def login(self) -> None:
        self.steam_login()
        self.backpack_login()
        print('Successfully logged in.')




    def logout(self) -> None:
        # stm logout?
        self.session.get(f"https://backpack.tf/logout?user-id={self.session.cookies.get_dict()['user-id']}")
        print('Successfully logged out.')






if __name__ == '__main__':
    loginSession = Login() 

    loginSession.login()
    time.sleep(5)
    loginSession.logout()