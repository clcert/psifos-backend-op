import logging
import uuid
import jwt

from app import config
from app.config import settings
from app.database import SessionLocal
from app.dependencies import get_db
from app.psifos.model import models, crud

from app.psifos_auth.model import models as auth_models
from app.psifos_auth.model import crud as auth_crud
from app.psifos_auth.model import schemas as auth_schemas


from fastapi import Depends, HTTPException, Request, Cookie
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash
from functools import update_wrapper, wraps
from requests_oauthlib import OAuth2Session

def get_auth_election(election_uuid: str, current_user: auth_models.User, db: Session):
    election = crud.get_election_by_uuid(db=db, uuid=election_uuid)
    if not election:
        raise HTTPException(status_code=400, detail="election not found")
    if election.admin_id != current_user.id:
        raise HTTPException(status_code=401, detail="election is not an admin election")
    
    return election

def create_user(username: str, password: str, db: Session = Depends(get_db)) -> str:
    """
    Create a new user
    :param username: username of the user
    :param password: password of the user
    """
    hashed_password = generate_password_hash(password, method="sha256")
    user = auth_schemas.UserIn(username=username, password=hashed_password, public_id=str(uuid.uuid4()))
    auth_crud.create_user(db=db, user=user)
    logging.log(msg="User created successfully!", level=logging.INFO)

# (***)
def get_user():
    """
    Get the user from the request

    """

    if config["AUTH"]["type_auth"] == "cas":
        if "username" not in session:
            return None

        return session["username"]

    elif config["AUTH"]["type_auth"] == "oauth":

        if "oauth_token" not in session:
            return None

        login = OAuth2Session(
            config["OAUTH"]["client_id"], token=session["oauth_token"]
        )
        user = login.get(config["OAUTH"]["user_info_url"]).json()
        return user["fields"]["username"]
