from datetime import timedelta
from fastapi import FastAPI

from .database import Base, engine
from .psifos.routes import api_router


Base.metadata.create_all(engine)

app = FastAPI()

app.config['CORS_HEADERS'] = 'Content-Type'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY']='Th1s1ss3cr3t'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1000)


app.include_router(api_router)


 