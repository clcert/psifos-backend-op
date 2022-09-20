from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from app.config import DATABASE_USER, DATABASE_PASS, DATABASE_HOST, DATABASE_NAME

# Database conn credentials
db_user = DATABASE_USER
db_pass = DATABASE_PASS
db_host = DATABASE_HOST
db_name = DATABASE_NAME

SQLALCHEMY_DATABASE_URL = "mysql://{0}:{1}@{2}/{3}".format(db_user, db_pass, db_host, db_name)

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
