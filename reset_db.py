from app.database import Base, engine 
from app.config import USE_ASYNC_ENGINE
from app.psifos_auth.utils import create_user
import asyncio

async def init_models():
    if USE_ASYNC_ENGINE:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
            await create_user("admin", "12345")
    else:
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        await create_user("admin", "12345")

if __name__ == "__main__":
    asyncio.run(init_models())
