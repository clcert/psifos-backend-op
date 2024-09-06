import logging
import uuid

from app.psifos.model import crud, models
from app.database import db_handler

from app.psifos_auth.model import models as auth_models
from app.psifos_auth.model import crud as auth_crud
from app.psifos_auth.model import schemas as auth_schemas
from app.psifos.model.enums import ElectionLoginTypeEnum

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash
from requests_oauthlib import OAuth2Session
from sqlalchemy.ext.asyncio import AsyncSession


async def get_auth_election(short_name: str, current_user: auth_models.User, session: Session | AsyncSession, status: str = None, simple: bool = False):
    election = await crud.get_election_by_short_name(session=session, short_name=short_name, simple=simple)
    if not election:
        raise HTTPException(status_code=404, detail="Election not found")
    if election.admin_id != current_user.id:
        raise HTTPException(status_code=401, detail="You are not the administrator of this election")
    if status is not None and election.election_status != status:
        raise HTTPException(status_code=400, detail="Election status check failed")

    return election

async def get_auth_voter_and_election(short_name: str, voter_login_id: str, session: Session | AsyncSession, status: str = None, election_params: list = None):

    if election_params:
        election_params = [*election_params, 
                           models.Election.id,
                           models.Election.election_login_type,
                           models.Election.election_status]
        election = await crud.get_election_params_by_name(session=session, short_name=short_name, params=election_params)
    else:
        election = await crud.get_election_by_short_name(session=session, short_name=short_name)
    if not election:
        raise HTTPException(status_code=404, detail="Election not found")
    
    voter = await crud.get_voter_by_login_id_and_election_id(session=session, voter_login_id=voter_login_id, election_id=election.id)
    
    if election.election_login_type == ElectionLoginTypeEnum.close_p:
        if not voter:
            raise HTTPException(status_code=400, detail="voter not found")
        if voter.voter_login_id != voter_login_id:
            raise HTTPException(status_code=401, detail="You are not allowed to access this voter")
    
    if status is not None and election.election_status != status:
        raise HTTPException(status_code=400, detail="Election status check failed")
    
    return voter, election


async def get_auth_trustee_and_election(short_name:str, trustee_uuid: str, login_id: str, session: Session | AsyncSession, status: str = None, simple: bool = False):
    election = await crud.get_election_by_short_name(session=session, short_name=short_name, simple=simple)
    if not election:
        raise HTTPException(status_code=404, detail="Election not found")
    
    trustee = await crud.get_trustee_by_uuid(session=session, uuid=trustee_uuid)
    if not trustee:
        raise HTTPException(status_code=400, detail="Trustee not found")
    if trustee.trustee_login_id != login_id:
        raise HTTPException(status_code=401, detail="You are not allowed to access this trustee")
    if trustee.election_id != election.id:
        raise HTTPException(status_code=401, detail="This trustee doesn't belong to this election")
    if status is not None and election.election_status != status:
        raise HTTPException(status_code=400, detail="Election status check failed")

    
    return trustee, election


@db_handler.func_with_session
async def create_user(session, username: str, password: str) -> str:
    """
    Create a new user
    :param username: username of the user
    :param password: password of the user
    """
    hashed_password = generate_password_hash(password, method="scrypt:32768:8:1")
    user = auth_schemas.UserIn(username=username, password=hashed_password, public_id=str(uuid.uuid4()))
    await auth_crud.create_user(session=session, user=user)
    logging.log(msg="User created successfully!", level=logging.INFO)

@db_handler.func_with_session
async def update_user(session, username: str, password: str) -> str:
    """
    Update the password of a user
    :param username: username of the user
    :param password: password of the user
    """
    hashed_password = generate_password_hash(password, method="scrypt:32768:8:1")
    await auth_crud.update_user(session=session, username=username, fields={"password": hashed_password})
    logging.log(msg="User updated successfully!", level=logging.INFO)
