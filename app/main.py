from datetime import timedelta
from fastapi import FastAPI

from app.config import settings

from .database import Base, engine
from .psifos.routes import api_router
from .psifos_auth.routes import auth_router

from fastapi.middleware.cors import CORSMiddleware

Base.metadata.create_all(engine)

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(api_router)
app.include_router(auth_router)
