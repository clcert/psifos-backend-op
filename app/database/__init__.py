from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from app import config

# Database conn credentials
db_user = config['local']['user']
db_pass = config['local']['password']
db_host = config['local']['host']
db_name = config['local']['database']

SQLALCHEMY_DATABASE_URL = "postgresql://{0}:{1}@{2}/{3}".format(db_user, db_pass, db_host, db_name)

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
