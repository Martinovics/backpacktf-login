# I'm just learning...

import rsa
import time
import base64
import requests
from bs4 import BeautifulSoup
from tools.guard import gen_steam_gurad_code
from tools.config import Config as cfg


''' Actual order:
bptf login
getrsakey
stm dologin
openid
'''



session = requests.Session()



# get rsa stuff
ourRsa = session.post('https://steamcommunity.com/login/getrsakey/', data={'username': cfg.username}).json()

ourRsa = {
    'modulus': int(ourRsa['publickey_mod'], 16),
    'exponent': int(ourRsa['publickey_exp'], 16),
    'publickey': None,
    'timestamp': int(ourRsa['timestamp']),
}
ourRsa['publickey'] = rsa.PublicKey(ourRsa['modulus'], ourRsa['exponent'])



# perform steam login
login_form = {
    'username': cfg.username,
    'password': base64.b64encode(rsa.encrypt(cfg.password.encode('UTF-8'), ourRsa['publickey'])),
    'twofactorcode': gen_steam_gurad_code(shared_secret=cfg.shared_secret),
    'emailauth': '',
    'loginfriendlyname': '',
    'captchagid': '-1',
    'captcha_text': '',
    'emailsteamid': '',
    'remember_login': 'false',
    'rsatimestamp': str(ourRsa['timestamp']),
    'donotcache': str(int(time.time() * 1000))
}

stm_login = session.post("https://store.steampowered.com/login/dologin", data=login_form).json()

if not stm_login['success']:
    raise Exception(stm_login['messsage'])

for url in stm_login['transfer_urls']:
    session.post(url, stm_login['transfer_parameters'])

''' Note:
session.cookies.get_dict()['steamLoginSecure']
'''

stm_login = session.cookies.get_dict()

session.cookies.set(**{
    "name": "sessionid",
    "value": stm_login['sessionid'],
    "domain": 'steamcommunity.com'
    })
session.cookies.set(**{
    "name": "sessionid",
    "value": stm_login['sessionid'],
    "domain": 'store.steampowered.com'
    })



bptf_login = session.post('https://backpack.tf/login')

soup = BeautifulSoup(bptf_login.text, "lxml")  # bptf_login.read() --> .decode(encoding='utf-8', errors='ignore')
bptf_login_params = {
    'action': soup.findAll("input", {"name": "action"})[0]['value'],
    'openidmode': soup.findAll("input", {"name": "openid.mode"})[0]['value'],
    'openidparams': soup.findAll("input", {"name": "openidparams"})[0]['value'],
    'nonce': soup.findAll("input", {"name": "nonce"})[0]['value']
}

session.post(bptf_login.url, data=bptf_login_params)
# print(session.get('https://backpack.tf/').content)


time.sleep(5)
print(session.cookies.get_dict()['user-id'])


session.get(f"https://backpack.tf/logout?user-id={session.cookies.get_dict()['user-id']}")
