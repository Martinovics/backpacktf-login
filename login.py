# I'm just learning...

import time
import requests
from bs4 import BeautifulSoup
from tools.guard import gen_steam_gurad_code
from tools.config import Config as cfg


session = requests.Session()

print('requesting backpack.tf')
resp = session.post('https://backpack.tf/login')

print(session.cookies)
print()
print(resp.content)


# rsa stuff
print('requesting steam')
rsa = session.post('https://steamcommunity.com/login/getrsakey/', data={'username': cfg.username})
print(rsa.content)


# doLogin params
login_form = {
    'username': cfg.username,
    'password': "",
    'twofactorcode': gen_steam_gurad_code(shared_secret=cfg.shared_secret),
    'emailauth': '',
    'loginfriendlyname': '',
    'captchagid': '-1',
    'captcha_text': '',
    'emailsteamid': '',
    'remember_login': 'false',
    'rsatimestamp': '244959050000',
    'donotcache': str(int(time.time() * 1000))
}


