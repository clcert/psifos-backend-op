
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from psifos.database import SessionLocal
from psifos.database import crud, schemas

from psifos.main import app

def get_db():
    """
    Database dependency: allows a single Session per request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


