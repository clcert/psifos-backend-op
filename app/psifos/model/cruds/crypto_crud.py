from app.psifos.model.schemas.crypto_schemas import PublicKeyBase
from app.psifos.model.crypto_models import PublicKey
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from app.database import db_handler

from sqlalchemy import select, update, delete


# Public Key

async def create_public_key(session: Session | AsyncSession, public_key: PublicKey | dict) -> PublicKey:

    db_public_key = PublicKey(**public_key) if isinstance(public_key, dict) else public_key
    db_handler.add(session, db_public_key)
    await db_handler.commit(session)
    await db_handler.refresh(session, db_public_key)
    return db_public_key

async def get_public_key(session: Session | AsyncSession, id: int):
    stmt = select(PublicKey).filter(PublicKey.id == id)
    result = await session.execute(stmt)
    return result.scalars().first()