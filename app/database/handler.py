from typing import Any
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import declarative_base
from app.config import USE_ASYNC_ENGINE

class AbstractHandler(object):
    """
    Holds the common behaviour of a database query handler.
    """
    def add(self, session: Session | AsyncSession, instance: Any):
        session.add(instance)


class AsyncHandler(AbstractHandler):
    """
    Database handler for asyncronous querying.
    """
    async def execute(self, session: AsyncSession, statement: Any):
        result = await session.execute(statement)
        return result

    async def refresh(self, session: AsyncSession, instance: Any):
        await session.refresh(instance)

    async def commit(self, session: AsyncSession):
        await session.commit()
    
    

class SyncHandler(AbstractHandler):
    """
    Database handler for syncronous querying.
    """
    async def execute(self, session: Session, statement: Any):
        result = session.execute(statement)
        return result

    async def refresh(self, session: AsyncSession, instance: Any):
        session.refresh(instance)

    async def commit(self, session: Session):
        session.commit()
    

class Database(object):
    """
    Abstraction layer for initializing 
    database parameters such as SessionLocal
    and the db handler.
    """
    @staticmethod
    def init_db(db_user, db_pass, db_host, db_name):
        Base = declarative_base()
        
        url_suffix = "://{0}:{1}@{2}/{3}".format(db_user, db_pass, db_host, db_name)
        
        if USE_ASYNC_ENGINE:
            db_url = "mysql+asyncmy" + url_suffix
            engine = create_async_engine(db_url) 
            session_class = AsyncSession
            db_handler = AsyncHandler()
        else: 
            db_url = "mysql" + url_suffix
            engine = create_engine(db_url)
            session_class = Session
            db_handler = SyncHandler()

        SessionLocal = sessionmaker(
            autocommit = False,
            autoflush = False,
            bind = engine,
            class_ = session_class,
            expire_on_commit = False
        )

        return Base, engine, SessionLocal, db_handler
