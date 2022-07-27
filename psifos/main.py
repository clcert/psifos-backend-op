from fastapi import FastAPI
from .database import models
from database import engine

models.Base.metadata.create_all(engine)

app = FastAPI()
 