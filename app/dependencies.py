from fastapi import Depends, Request, HTTPException
from app.database import SessionLocal
from sqlalchemy.orm import Session
from app.psifos_auth.model import models, crud
from app.config import settings

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


def verify_token(request: Request, db: Session = Depends(get_db)):
    """
    User dependency: allows a single User per request.
    """

    token = request.headers.get("x-access-tokens", None)
    if not token:
        raise HTTPException(status_code=401, detail="a valid token is missing")

    try:
        data = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        return crud.get_user_by_public_id(public_id=data["public_id"], db=db)

    except:
        raise HTTPException(status_code=401, detail="token is invalid")

