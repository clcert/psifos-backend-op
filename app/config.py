from datetime import timedelta

import os

# Retrieve enviroment variables from .env file

DATABASE_USER = os.environ.get("DATABASE_USER")
DATABASE_PASS = os.environ.get("DATABASE_PASS")
DATABASE_HOST = os.environ.get("DATABASE_HOST")
DATABASE_NAME = os.environ.get("DATABASE_NAME")

SECRET_KEY: str = os.environ.get("SECRET_KEY")

APP_FRONTEND_URL = os.environ.get("APP_FRONTEND_URL")
APP_BACKEND_OP_URL = os.environ.get("APP_BACKEND_OP_URL")
APP_BACKEND_INFO_URL = os.environ.get("APP_BACKEND_INFO_URL")

TYPE_AUTH = os.environ.get("TYPE_AUTH")

CAS_URL = os.environ.get("CAS_URL")

OAUTH_TOKEN_URL = os.environ.get("OAUTH_TOKEN_URL")
OAUTH_AUTHORIZE_URL = os.environ.get("OAUTH_AUTHORIZE_URL")
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID")
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET")
OAUTH_USER_INFO_URL = os.environ.get("OAUTH_USER_INFO_URL")

USE_ASYNC_ENGINE = bool(int(os.environ.get("USE_ASYNC_ENGINE", False)))
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND")

ORIGINS: list = [
    "*"
]