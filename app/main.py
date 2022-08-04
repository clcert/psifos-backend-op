from datetime import timedelta
from fastapi import FastAPI

from .database import Base, engine
from .psifos.routes import api_router


Base.metadata.create_all(engine)

app = FastAPI()
app.include_router(api_router)
