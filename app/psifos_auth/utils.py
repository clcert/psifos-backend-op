import logging
import uuid

from app.psifos.model import crud
from app.database import db_handler

from app.psifos_auth.model import models as auth_models
from app.psifos_auth.model import crud as auth_crud
from app.psifos_auth.model import schemas as auth_schemas

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash
from requests_oauthlib import OAuth2Session
from sqlalchemy.ext.asyncio import AsyncSession


async def get_auth_election(election_uuid: str, current_user: auth_models.User, session: Session | AsyncSession, status: str = None):
    election = await crud.get_election_by_uuid(session=session, uuid=election_uuid)
    if not election:
        raise HTTPException(status_code=404, detail="Election not found")
    if election.admin_id != current_user.id:
        raise HTTPException(status_code=401, detail="You are not the administrator of this election")
    if status is not None and election.status != status:
        raise HTTPException(status_code=400, detail="Election status check failed")

    return election

async def get_auth_voter_and_election(election_uuid: str, voter_login_id: str, session: Session | AsyncSession, status: str = None):
    election = await crud.get_election_by_uuid(session=session, uuid=election_uuid)
    voter = await crud.get_voter_by_login_id_and_election_id(session=session, voter_login_id=voter_login_id, election_id=election.id)
    if not voter:
        raise HTTPException(status_code=400, detail="voter not found")
    if voter.voter_login_id != voter_login_id:
        raise HTTPException(status_code=401, detail="You are not allowed to access this voter")
    if status is not None and election.status != status:
        raise HTTPException(status_code=400, detail="Election status check failed")
    
    return voter, election

async def get_auth_trustee_and_election(election_uuid:str, trustee_uuid: str, login_id: str, session: Session | AsyncSession, status: str = None):
    election = await crud.get_election_by_uuid(session=session, uuid=election_uuid)
    trustee = await crud.get_trustee_by_uuid(session=session, uuid=trustee_uuid)
    if not trustee:
        raise HTTPException(status_code=400, detail="Trustee not found")
    if trustee.trustee_login_id != login_id:
        raise HTTPException(status_code=401, detail="You are not allowed to access this trustee")
    if trustee.election_id != election.id:
        raise HTTPException(status_code=401, detail="This trustee doesn't belong to this election")
    if status is not None and election.status != status:
        raise HTTPException(status_code=400, detail="Election status check failed")

    
    return trustee, election


@db_handler.func_with_session
async def create_user(session, username: str, password: str) -> str:
    """
    Create a new user
    :param username: username of the user
    :param password: password of the user
    """
    hashed_password = generate_password_hash(password, method="sha256")
    user = auth_schemas.UserIn(username=username, password=hashed_password, public_id=str(uuid.uuid4()))
    await auth_crud.create_user(session=session, user=user)
    logging.log(msg="User created successfully!", level=logging.INFO)
