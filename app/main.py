from fastapi import FastAPI

from .psifos.routes import api_router
from .psifos_auth.routes import auth_router

# from api_analytics.fastapi import Analytics

from app.logger import logger
from app.middleware import register_middlewares

app = FastAPI()

app.logger = logger

register_middlewares(app)

# Routes
app.include_router(api_router)
app.include_router(auth_router)
