from app.database.handler import Database
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine


from app.config import DATABASE_USER, DATABASE_PASS, DATABASE_HOST, DATABASE_NAME

# Database conn credentials
db_user = DATABASE_USER
db_pass = DATABASE_PASS
db_host = DATABASE_HOST
db_name = DATABASE_NAME

# Init database
Base, engine, SessionLocal, db_handler = Database.init_db(db_user, db_pass, db_host, db_name)