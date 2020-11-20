import rsa
from base64 import b64encode
import json

import time
import asyncio
import aiohttp
from typing import Optional, Any, Tuple

from tools.config import Const as const
from tools.config import Config as cfg



async def json_or_text(r: aiohttp.ClientResponse) -> Optional[Any]:
    text = await r.text()
    try:
        if "application/json" in r.headers["Content-Type"]:
            return json.loads(text)
    except KeyError:
        pass
    return text





class Client:

    def __init__(self, **options: Any):
        self.loop = asyncio.get_event_loop()
        self.http = HTTPClient(client=self)

        self.username: Optional[str] = None
        self.api_key: Optional[str] = None
        self.password: Optional[str] = None
        self.shared_secret: Optional[str] = None
        self.identity_secret: Optional[str] = None
        self.token: Optional[str] = None



    async def login(self, username: str, password: str, *, shared_secret: Optional[str] = None) -> None:
        '''
        self.username = username
        self.password = password
        self.shared_secret = shared_secret
        '''

        await self.http.login(username, password, shared_secret=shared_secret)




class HTTPClient:
    
    def __init__(self, client: Client):
        self._session: Optional[aiohttp.ClientSession] = None  # filled in login
        self._client = client

        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.api_key: Optional[str] = None
        self.shared_secret: Optional[str] = None
        self._one_time_code = ""
        self._email_code = ""
        self._captcha_id = "-1"
        self._captcha_text = ""
        self._steam_id = ""

        self.session_id: Optional[str] = None
        self.user = None
        self.logged_in = False
        self.user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36"
        )



    async def request(self, method: str, url, **kwargs: Any) -> Optional[Any]:  # adapted from d.py
        kwargs["headers"] = {"User-Agent": self.user_agent, **kwargs.get("headers", {})}
        #payload = kwargs.get("data")

        for tries in range(5):
            async with self._session.request(method, url, **kwargs) as r:

                # even errors have text involved in them so this is safe to call
                data = await json_or_text(r)

                # the request was successful so just return the text/json
                if 200 <= r.status < 300:
                    return data

                # we are being rate limited
                elif r.status == 429:
                    # I haven't been able to get any X-Retry-After headers
                    # from the API but we should probably still handle it
                    try:
                        await asyncio.sleep(float(r.headers["X-Retry-After"]))
                    except KeyError:  # steam being un-helpful as usual
                        await asyncio.sleep(2 ** tries)
                    continue

                # we've received a 500 or 502, an unconditional retry
                elif r.status in {500, 502}:
                    await asyncio.sleep(1 + tries * 3)
                    continue

                # been logged out
                elif 300 <= r.status <= 399 and "login" in r.headers.get("location", ""):
                    await self.login(self.username, self.password, self.shared_secret)
                    continue

                elif r.status == 401:
                    if not data:
                        # raise errors.HTTPException(r, data)
                        raise SyntaxError(f"request error: {r.status}")
                    # api key either got revoked or it was never valid
                    if "Access is denied. Retrying will not help. Please verify your <pre>key=</pre>" in data:
                        # time to fetch a new key
                        # self._client.api_key = self.api_key = kwargs["key"] = await self.get_api_key()
                        # retry with our new key
                        pass

                # the usual error cases
                elif r.status == 403:
                    #raise errors.Forbidden(r, data)
                    raise SyntaxError("Forbidden")
                elif r.status == 404:
                    #raise errors.NotFound(r, data)
                    raise SyntaxError("NotFound")
                else:
                    #raise errors.HTTPException(r, data)
                    raise SyntaxError("HTTPException")

        # we've run out of retries, raise
        # raise errors.HTTPException(r, data)
        raise SyntaxError("we've run out of retries")




    async def login(self, username: str, password: str, shared_secret: Optional[str]) -> None:
        self.username = username
        self.password = password
        self.shared_secret = shared_secret

        self._session = aiohttp.ClientSession()

        resp = await self._send_login_request()

        if resp.get("captcha_needed") and resp.get("message") != "Please wait and try again later.":
            self._captcha_id = resp["captcha_gid"]
            print(
                "Please enter the captcha text at"
                f" https://steamcommunity.com/login/rendercaptcha/?gid={resp['captcha_gid']}"
            )
            # captcha_text = await utils.ainput(">>> ")
            # self._captcha_text = captcha_text.strip()
            return await self.login(username, password, shared_secret)
        if not resp["success"]:
            # raise errors.InvalidCredentials(resp.get("message", "An unexpected error occurred"))
            raise SyntaxError(resp.get("message", "An unexpected error occurred"))

        data = resp.get("transfer_parameters")
        if data is None:
            '''
            raise errors.LoginError(
                "Cannot perform redirects after login. Steam is likely down, please try again later."
            )
            '''
            raise SyntaxError("Cannot perform redirects after login. Steam is likely down, please try again later.")

        for url in resp["transfer_urls"]:
            await self.request("POST", url=url, data=data)

        

        cookies = self._session.cookie_jar.filter_cookies("https://steamcommunity.com")
        self.session_id = cookies["sessionid"].value

        '''
        resp = await self.get_user(resp["transfer_parameters"]["steamid"])
        data = resp["response"]["players"][0]
        state = self._client._connection
        self.user = ClientUser(state=state, data=data)
        state._users[self.user.id64] = self.user
        self.logged_in = True
        self._client.dispatch("login")
        '''
    

    async def _get_rsa_params(self, current_repetitions: int = 0):
        payload = {"username": self.username, "donotcache": int(time.time() * 1000)}
        try:
            key_response = await self.request("POST", "https://steamcommunity.com/login/getrsakey", data=payload)
        except Exception as exc:
            exc
            # raise errors.LoginError("Failed to get RSA key") from exc
            raise SyntaxError("Failed to get RSA key")
        try:
            n = int(key_response["publickey_mod"], 16)
            e = int(key_response["publickey_exp"], 16)
            rsa_timestamp = key_response["timestamp"]
        except KeyError:
            if current_repetitions < 5:
                return await self._get_rsa_params(current_repetitions + 1)
            raise ValueError("Could not obtain rsa-key")
        else:
            return b64encode(rsa.encrypt(self.password.encode("utf-8"), rsa.PublicKey(n, e))), rsa_timestamp


    async def _send_login_request(self) -> dict:
        password, timestamp = await self._get_rsa_params()
        payload = {
            "username": self.username,
            "password": password.decode(),
            "emailauth": self._email_code,
            "emailsteamid": self._steam_id,
            "twofactorcode": self._one_time_code,
            "captchagid": self._captcha_id,
            "captcha_text": self._captcha_text,
            "loginfriendlyname": self.user_agent,
            "rsatimestamp": timestamp,
            "remember_login": True,
            "donotcache": int(time.time() * 1000),
        }
        try:
            resp = await self.request("POST", "https://steamcommunity.com/login/dologin", data=payload)
            '''
            if resp.get("requires_twofactor"):
                self._one_time_code = await self._client.code()
            elif resp.get("emailauth_needed"):
                self._steam_id = resp.get("emailsteamid")
                self._email_code = await self._client.code()
            else:
                return resp
            '''
            return await self._send_login_request()
        except Exception as exc:
            exc
            #raise errors.LoginError from exc
            raise SyntaxError("steam login error")


    async def close(self) -> None:
        await self.logout()
        await self._session.close()

    async def logout(self) -> None:
        payload = {"sessionid": self.session_id}
        await self.request("POST", "https://steamcommunity.com/login/logout", data=payload)
        self.logged_in = False
        self.user = None
        





async def main():

    async with aiohttp.ClientSession(headers={'User-Agent': const.USER_AGENT}) as session:

        await Client.login(cfg.USERNAME, cfg.PASSWORD, cfg.SHARED_SECRET)
        await asyncio.sleep(5)
        




if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
