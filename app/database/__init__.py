from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from app.config import env

# Database conn credentials
db_user = env['local']['user']
db_pass = env['local']['password']
db_host = env['local']['host']
db_name = env['local']['database']

SQLALCHEMY_DATABASE_URL = "mysql://{0}:{1}@{2}/{3}".format(db_user, db_pass, db_host, db_name)

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
