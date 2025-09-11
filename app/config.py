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

MIXNET_01_NAME = os.environ.get("MIXNET_01_NAME", "mixserver01")
MIXNET_01_URL = os.environ.get("MIXNET_01_URL", "http://mixserver01:8000")
MIXNET_02_NAME = os.environ.get("MIXNET_02_NAME", "mixserver02")
MIXNET_02_URL = os.environ.get("MIXNET_02_URL", "http://mixserver02:8000")
MIXNET_03_NAME = os.environ.get("MIXNET_03_NAME", "mixserver03")
MIXNET_03_URL = os.environ.get("MIXNET_03_URL", "http://mixserver03:8000")
MIXNET_TOKEN =  os.environ.get("MIXNET_TOKEN")
MIXNET_WIDTH = int(os.environ.get("MIXNET_WIDTH", 6))
MIXNET_WAIT_INTERVAL = int(os.environ.get("MIXNET_WAIT_INTERVAL", 5))

TYPE_AUTH = os.environ.get("TYPE_AUTH")

CAS_URL = os.environ.get("CAS_URL")

OAUTH_GOOGLE = bool(int(os.environ.get("OAUTH_GOOGLE", False)))

OAUTH_TOKEN_URL = os.environ.get("OAUTH_TOKEN_URL")
OAUTH_AUTHORIZE_URL = os.environ.get("OAUTH_AUTHORIZE_URL")
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID")
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET")
OAUTH_USER_INFO_URL = os.environ.get("OAUTH_USER_INFO_URL")

OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET")
OIDC_PROVIDER_URL = os.environ.get("OIDC_PROVIDER_URL")
OIDC_AUTHORIZE_URL = os.environ.get("OIDC_AUTHORIZE_URL")
OIDC_TOKEN_URL = os.environ.get("OIDC_TOKEN_URL")

ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")

USE_ASYNC_ENGINE = bool(int(os.environ.get("USE_ASYNC_ENGINE", False)))
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND")
TIMEZONE = os.environ.get("TIMEZONE", "Chile/Continental")
TOKEN_ANALYTICS_OP = os.environ.get("TOKEN_ANALYTICS_OP")

ORIGINS: list = [
    "*"
]