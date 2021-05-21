import re
import time
import requests
from bs4 import BeautifulSoup

import rsa
import hmac
import base64
import hashlib

try:
    # from tools.config import Const as const
    from tools.config import Config as cfg
except ImportError:
    ex = "Please, fill out the 'config_temp.py' file with the needed information, then rename it to just 'config.py'."
    raise Exception(ex)






class Login:

    def __init__(self, session: requests.Session = requests.Session()):
        self.session = session
        self.logged_in = 0        # --> epoch
        self.bptf_logged_in = 0   # --> epoch
        self.steam_logged_in = 0  # --> epoch
        self.bptf_logout_url = 'https://backpack.tf/logout'  # not complete yet




    @classmethod
    def elapsed_time(self, seconds: [int, float]) -> str:
        seconds = int(seconds)

        hour = seconds // 3600
        minute = (seconds - hour * 3600) // 60
        second = seconds - hour * 3600 - minute * 60

        return f'{hour}h{minute}m{second}s'




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




    @classmethod
    def check_error(self, status: int = 200, expected_status: int = 200, err_messsage: str = '') -> None:

        if err_messsage:
            raise Exception(err_messsage)
        if status != expected_status or err_messsage:
            raise Exception(f'There was an error. Expected status: {expected_status}, actual status: {status}')




    def get_session(self) -> requests.Session:
        return self.session


    def is_logged_in(self) -> bool:
        return bool(self.logged_in)


    def is_bptf_logged_in(self) -> bool:
        return bool(self.bptf_logged_in)


    def is_steam_logged_in(self) -> bool:
        return bool(self.steam_logged_in)




    def steam_login(self) -> None:

        resp = self.session.post('https://steamcommunity.com/login/getrsakey/', data={'username': cfg.USERNAME})
        self.check_error(resp.status_code)
        ourRsa = resp.json()


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


        resp = self.session.post("https://store.steampowered.com/login/dologin", data=payload)
        self.check_error(resp.status_code)
        resp = resp.json()

        for url in resp['transfer_urls']:
            self.session.post(url, data=resp['transfer_parameters'])


        '''
        cookies = self.session.cookies.get_dict()
        self.session.cookies.set(**{"name": "sessionid", "value": cookies['sessionid'], "domain": 'steamcommunity.com'})
        self.session.cookies.set(**{"name": "sessionid", "value": cookies['sessionid'],
                                 "domain": 'store.steampowered.com'})
        '''


        # check whether we are really logged in
        resp = self.session.get('https://steamcommunity.com')
        self.check_error(resp.status_code)
        resp = resp.text

        try:
            regex = r'<a href="https://steamcommunity.com/profiles/(.*?)/" data-miniprofile="(.*?)">(.*?)</a>'
            steamID64, _, username = re.findall(regex, resp)[0]
        except (ValueError, IndexError):
            raise Exception('some exception')

        self.steam_logged_in = time.time()
        print(f'Successfully logged in to steam as {username} ({steamID64}).')




    def backpack_login(self) -> None:

        resp = self.session.post('https://backpack.tf/login')
        self.check_error(resp.status_code)

        soup = BeautifulSoup(resp.text, "lxml")
        inputs = soup.find("form", id="openidForm").find_all('input')
        payload = {field['name']: field['value'] for field in inputs if 'name' in field.attrs}

        resp = self.session.post(resp.url, data=payload)
        self.check_error(resp.status_code)


        # check whether we are really logged in
        resp = self.session.get('https://backpack.tf')  # actually this was the final destination of the prev request
        self.check_error(resp.status_code)
        resp = re.sub(r'[\t\n]', '', resp.text).replace('    ', '')

        try:
            steamID64, username = re.findall(r'<a href="/profiles/(.*?)">(.*?)</a>', resp)[0]

            user_id = re.findall(r"<a href='/logout\?user-id=(.*?)'>", resp)[0]
            self.bptf_logout_url = f"https://backpack.tf/logout?user-id={user_id}"
        except (ValueError, IndexError):
            raise Exception('some exception')

        self.bptf_logged_in = time.time()
        print(f'Successfully logged in to backpack.tf as {username} ({steamID64}).')




    def login(self) -> None:
        self.steam_login()
        self.backpack_login()

        if not (self.steam_logged_in and self.bptf_logged_in):
            self.check_error(err_messsage='There was an error while logging in.')

        self.logged_in = time.time()
        print('Successfully logged in.')




    def steam_logout(self) -> None:

        resp = self.session.post(url='https://steamcommunity.com/login/logout/',
                                 data={'sessionid': self.session.cookies.get_dict()['sessionid']})
        self.check_error(resp.status_code)

        self.steam_logged_in = 0
        print('Successfully logged out from steam.')




    def backpack_logout(self) -> None:

        resp = self.session.get(self.bptf_logout_url)
        self.check_error(resp.status_code)

        self.bptf_logged_in = 0
        print('Successfully logged out from backpack.tf.')




    def logout(self) -> None:
        self.steam_logout()
        self.backpack_logout()

        if self.steam_logged_in or self.bptf_logged_in:
            self.check_error(err_messsage='There was an error while logging out.')

        time.sleep(0.1)
        self.session.close()

        print(f'Successfully logged out. Session lasted for {self.elapsed_time(time.time()-self.logged_in)}.')
        self.logged_in = 0






if __name__ == '__main__':
    loginSession = Login()

    loginSession.login()
    time.sleep(5)
    loginSession.logout()
