import configparser
from datetime import timedelta
from pydantic import BaseSettings

# Retrieve enviroment variables from .env file
env = configparser.ConfigParser()
env.read(".env")


class Settings(BaseSettings):
    CORS_HEADERS: str = "Content-Type"
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = True
    SECRET_KEY: str = "Th1s1ss3cr3t"
    JWT_ACCESS_TOKEN_EXPIRES: timedelta = timedelta(hours=1000)
    ORIGINS = [
        "http://localhost",
        "http://localhost:3000",
    ]


settings = Settings()
