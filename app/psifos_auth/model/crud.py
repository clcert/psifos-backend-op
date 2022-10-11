from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.psifos_auth.model import models, schemas
from app.database import db_handler

async def get_user_by_public_id(session: Session | AsyncSession, public_id: str):
    query = select(models.User).where(models.User.public_id == public_id)
    result = await db_handler.execute(session, query)
    return result.scalars().first()

async def get_user_by_name(session: Session | AsyncSession, name: str):
    query = select(models.User).where(models.User.username == name)
    result = await db_handler.execute(session, query)
    return result.scalars().first()


async def create_user(session: Session | AsyncSession, user: schemas.UserIn):
    db_user = models.User(**user.dict())
    db_handler.add(session, db_user)
    await db_handler.commit(session) 
    await db_handler.refresh(session, db_user)
    return db_user