from app.config import USE_ASYNC_ENGINE
from app.database import SessionLocal
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session


async def get_session() -> Session | AsyncSession:
    """
    Database dependency: allows a single Session per request.
    """   
    if USE_ASYNC_ENGINE:
        async with SessionLocal() as session:
            yield session
    else:
        with SessionLocal() as session:
            yield session