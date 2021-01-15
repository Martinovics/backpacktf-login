import os
import asyncio
from steam.ext import commands
from config import config as cfg

from bs4 import BeautifulSoup
import aiohttp
import asyncio

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
    await bot.http.request("POST", "https://steamcommunity.com/openid/login", data=payload)
    resp = await bot.http.request("GET", "https://backpack.tf/")
    resp = await resp.read()
    print(resp.decode(encoding='utf-8', errors='ignore'))
    print('\n\n\n')
    resp = await resp.text()
    print(resp)
    
    await asyncio.sleep(3)
    await bot.close()



@bot.command(aliases=['recogs'])
async def reload_cogs(ctx):
    for f in os.listdir('./cogs'):
        if f.endswith('.py'):
            bot.unload_extension(f'cogs.{f[:-3]}')
            await asyncio.sleep(0.1)
            bot.load_extension(f'cogs.{f[:-3]}')

    await ctx.send(f"reloaded cogs")
    return




for file in os.listdir('./cogs'):
    if file.endswith('.py'):
        bot.load_extension(f'cogs.{file[:-3]}')




bot.run(  # don't use api_key argument or it will crash:/
    username=cfg['username'],
    password=cfg['password'],
    shared_secret=cfg['shared_secret'],
    identity_secret=cfg['identity_secret']
)
