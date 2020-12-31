import asyncio
import aiohttp

from tools.config import Config as cfg
from tools.config import Const as const




async def main():
    
    async with aiohttp.ClientSession(headers={'User-Agent': const.USER_AGENT}) as session:

        resp = await session.post('https://backpack.tf/login')
        print(resp.status)

        resp = await session.get(resp.url)
        print(resp.status)
        print(resp.text)











if __name__  == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
