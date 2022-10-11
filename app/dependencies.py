from app.database import SessionLocal
from sqlalchemy.ext.asyncio import AsyncSession


async def get_session() -> AsyncSession:
    """
    Database dependency: allows a single Session per request.
    """   
    async with SessionLocal() as session:
        yield session
