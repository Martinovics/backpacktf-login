import asyncio
from bs4 import BeautifulSoup
from steam.ext import commands

from tools.config_bot_temp import Config as cfg




bot = commands.Bot(command_prefix=('.', '!'))




@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} with an id of {bot.user.id64}")
    resp = await bot.http.request("POST", "https://backpack.tf/login")
    soup = BeautifulSoup(resp, "html.parser")
    payload = {
        field["name"]: field["value"]
        for field in soup.find("form", id="openidForm").find_all("input")
        if "name" in field.attrs
    }
    resp = await bot.http.request("POST", "https://steamcommunity.com/openid/login", data=payload)
    print(resp)

    asyncio.sleep(0.1)

    resp = await bot.http.request("GET", "https://backpack.tf/")
    print(resp)

    await asyncio.sleep(3)
    await bot.close()






bot.run(  # don't use api_key argument or it will crash:/
    username=cfg.USERNAME,
    password=cfg.PASSWORD,
    shared_secret=cfg.SHARED_SECRET,
    identity_secret=cfg.IDENTITY_SECRET
)
