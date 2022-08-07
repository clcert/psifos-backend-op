from fastapi import Depends, Request, HTTPException
from app.database import SessionLocal
from sqlalchemy.orm import Session
from app.psifos_auth.model import models, crud
from app.config import settings

from fastapi import Depends, HTTPException


import jwt


def get_db():
    """
    Database dependency: allows a single Session per request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
