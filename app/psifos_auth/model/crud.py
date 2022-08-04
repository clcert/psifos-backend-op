from sqlalchemy.orm import Session
from app.psifos_auth.model import models, schemas

def get_user_by_public_id(db: Session, public_id: str):
    return db.query(models.User).filter(models.User.public_id == public_id).first()

def get_user_by_name(db: Session, name: str):
    return db.query(models.User).filter(models.User.name == name).first()

def create_user(db: Session, user: schemas.UserIn):
    db_user = models.User(**user.dict())
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user