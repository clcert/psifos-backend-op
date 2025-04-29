from app.psifos.model.schemas.crypto_schemas import SecretKeyBase
from app.psifos.model.crypto_models import PublicKey, SecretKey
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

async def delete_public_key(session: Session | AsyncSession, id: int):
    stmt = delete(PublicKey).where(PublicKey.id == id)
    await session.execute(stmt)
    await db_handler.commit(session)
    return True

async def delete_unused_public_keys(session: AsyncSession):
    # Consulta para encontrar las claves públicas que no están asociadas a ninguna elección o trustee
    stmt = select(PublicKey).filter(
        ~PublicKey.elections.has(),  # No tiene elecciones asociadas
        ~PublicKey.trustees.has()    # No tiene trustees asociados
    )
    
    result = await session.execute(stmt)
    unused_keys = result.scalars().all()

    # Eliminar claves públicas no usadas
    for key in unused_keys:
        await delete_public_key(session, key.id)

    return {"message": f"Deleted {len(unused_keys)} unused public keys."}

## Secret Key
async def create_secret_key(session: Session | AsyncSession, secret_key: SecretKeyBase) -> SecretKey:
    db_secret_key = secret_key if isinstance(secret_key, SecretKey) else SecretKey(**secret_key.dict())
    db_secret_key.x = str(db_secret_key.x)
    db_handler.add(session, db_secret_key)
    await db_handler.commit(session)
    await db_handler.refresh(session, db_secret_key)
    return db_secret_key
