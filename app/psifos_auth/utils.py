import logging
import uuid

from app import config
from app.database import SessionLocal
from app.psifos.model import crud

from app.psifos_auth.model import models as auth_models
from app.psifos_auth.model import crud as auth_crud
from app.psifos_auth.model import schemas as auth_schemas

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash
from requests_oauthlib import OAuth2Session


def get_auth_election(election_uuid: str, current_user: auth_models.User, db: Session):
    election = crud.get_election_by_uuid(db=db, uuid=election_uuid)
    if not election:
        raise HTTPException(status_code=400, detail="Election not found")
    if election.admin_id != current_user.id:
        raise HTTPException(status_code=401, detail="You are not the administrator of this election")

    return election

def get_auth_voter_and_election(election_uuid: str, login_id: str, db: Session):
    election = crud.get_election_by_uuid(db=db, uuid=election_uuid)
    voter = crud.get_voter_by_login_id_and_election_id(db=db, login_id=login_id, election_id=election.id)
    if not voter:
        raise HTTPException(status_code=400, detail="voter not found")
    if voter.voter_login_id != login_id:
        raise HTTPException(status_code=401, detail="You are not allowed to access this voter")
    
    return voter, election

def get_auth_trustee_and_election(election_uuid:str, trustee_uuid: str, login_id: str, db: Session):
    election = crud.get_election_by_uuid(db=db, uuid=election_uuid)
    trustee = crud.get_trustee_by_uuid(db=db, uuid=trustee_uuid)
    if not trustee:
        raise HTTPException(status_code=400, detail="Trustee not found")
    if trustee.trustee_login_id != login_id:
        raise HTTPException(status_code=401, detail="You are not allowed to access this trustee")
    if trustee.election_id != election.id:
        raise HTTPException(status_code=401, detail="This trustee doesn't belong to this election")

    
    return trustee, election





def create_user(username: str, password: str) -> str:
    """
    Create a new user
    :param username: username of the user
    :param password: password of the user
    """
    hashed_password = generate_password_hash(password, method="sha256")
    user = auth_schemas.UserIn(username=username, password=hashed_password, public_id=str(uuid.uuid4()))
    with SessionLocal() as db:
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

        login = OAuth2Session(config["OAUTH"]["client_id"], token=session["oauth_token"])
        user = login.get(config["OAUTH"]["user_info_url"]).json()
        return user["fields"]["username"]
