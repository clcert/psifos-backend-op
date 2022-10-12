from app.config import USE_ASYNC_ENGINE
from app.database import SessionLocal
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session


async def get_session() -> Session | AsyncSession:
    """
    Database dependency: allows a single Session per request.
    """   

    async with SessionLocal() as session:
        yield session
