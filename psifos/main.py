from fastapi import FastAPI
from database import models, engine

models.Base.metadata.create_all(engine)

app = FastAPI()
 