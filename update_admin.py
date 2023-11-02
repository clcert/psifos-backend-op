from app.database import Base, engine 
from app.config import USE_ASYNC_ENGINE
from app.psifos_auth.utils import update_user
import asyncio
import sys

async def init_models():
    if USE_ASYNC_ENGINE:
        async with engine.begin() as conn:
            await update_user(sys.argv[1], sys.argv[2])
    else:
        await update_user(sys.argv[1], sys.argv[2])

if __name__ == "__main__":
    asyncio.run(init_models())
