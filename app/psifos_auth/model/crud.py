from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
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

async def update_user(session: Session | AsyncSession, username: str, fields: dict):
    query = update(models.User).where(
        models.User.username == username
    ).values(fields)
    await db_handler.execute(session, query)
    await db_handler.commit(session)

    return await get_user_by_name(session=session, name=username)

async def relation_election_admins(session: Session | AsyncSession, election_id: int, user_id: int):
    db_election_admin = models.ElectionAdmins(
        election_id=election_id,
        user_id=user_id
    )
    db_handler.add(session, db_election_admin)
    await db_handler.commit(session)
    await db_handler.refresh(session, db_election_admin)
    return db_election_admin
