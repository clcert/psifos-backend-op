from typing import Any

from app.config import USE_ASYNC_ENGINE
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker


class AbstractHandler(object):
    """
    Holds the common behaviour of a database query handler.
    """

    def __init__(self, session_local) -> None:
        self.session_local = session_local

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

    def func_with_session(self, func):
        session_local = self.session_local

        async def wrapper(*args, **kwargs):
            async with session_local() as session:
                return await func(session, *args, **kwargs)

        return wrapper

    def method_with_session(self, method):
        session_local = self.session_local

        async def wrapper(self, *args, **kwargs):
            async with session_local() as session:
                return await method(self, session, *args, **kwargs)

        return wrapper


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

    def func_with_session(self, func):
        session_local = self.session_local

        async def wrapper(*args, **kwargs):
            with session_local() as session:
                return await func(session, *args, **kwargs)

        return wrapper

    def method_with_session(self, method):
        session_local = self.session_local

        async def wrapper(self, *args, **kwargs):
            with session_local() as session:
                return await method(self, session, *args, **kwargs)

        return wrapper


class Database(object):
    """
    Abstraction layer for initializing
    database parameters such as SessionLocal
    and the db handler.
    """

    engine_options = {
        "pool_recycle": 3600
    }

    @staticmethod
    def init_db(db_user, db_pass, db_host, db_name):
        Base = declarative_base()

        url_suffix = "://{0}:{1}@{2}/{3}".format(db_user, db_pass, db_host, db_name)

        if USE_ASYNC_ENGINE:
            db_url = "mysql+asyncmy" + url_suffix
            engine = create_async_engine(db_url, **Database.engine_options)
            session_class = AsyncSession
        else:
            db_url = "mysql" + url_suffix
            engine = create_engine(db_url, **Database.engine_options)
            session_class = Session

        SessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=engine, class_=session_class, expire_on_commit=False
        )

        handler_class = AsyncHandler if USE_ASYNC_ENGINE else SyncHandler
        db_handler = handler_class(SessionLocal)

        return Base, engine, SessionLocal, db_handler
