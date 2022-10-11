from app.database import Base, engine 
from app.psifos_auth.utils import create_user
import asyncio

async def init_models():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        await create_user("admin", "12345")

if __name__ == "__main__":
    asyncio.run(init_models())
