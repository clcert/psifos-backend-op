import logging
import uuid
import jwt

from app import config
from app.config import settings
from app.dependencies import get_db
from app.psifos.model import models, crud

from app.psifos_auth.model import models as auth_models
from app.psifos_auth.model import crud as auth_crud
from app.psifos_auth.model import schemas as auth_schemas


from fastapi import Depends, HTTPException, Request
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


def token_required(func):
    """
    Decorator to check if the user is logged in

    """

    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        token = request.headers.get("x-access-tokens", None)
        if not token:
            raise HTTPException(status_code=401, detail="a valid token is missing")

        try:
            data = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            current_user = crud.get_user_by_public_id(public_id=data["public_id"])

        except:
            raise HTTPException(status_code=401, detail="token is invalid")

        return await func(current_user, *args, **kwargs)

    return wrapper


def election_route(**kwargs):
    """
    Decorator to check if the election is an admin election

    """

    admin_election = kwargs.get("admin_election", True)

    def election_route_decorator(f):
        async def election_route_wrapper(
            current_user=None, election_uuid=None, *args, **kwargs
        ):
            election = Election.get_by_uuid(uuid=election_uuid)
            if not election:
                raise HTTPException(status_code=400, detail="election not found")
            if admin_election and election.admin_id != current_user.id:
                raise HTTPException(status_code=401, detail="election is not an admin election")

            return await f(election, *args, **kwargs)

        return update_wrapper(election_route_wrapper, f)

    return election_route_decorator


def auth_requires(f: callable) -> callable:
    @wraps(f)
    async def decorator(request: Request, *args, **kwargs):
        if "username" not in request.session and "oauth_token" not in request.session:
            raise HTTPException(status_code = 401, detail = "unauthorized user")

        user_session = get_user()

        return await f(user_session, *args, **kwargs)

    return decorator


def voter_cas(**kwargs):
    """
    Decorator to check if the voter is registered in the election

    """

    def voter_cas_decorator(f):
        async def voter_cas_wrapper(user_session=None, election_uuid=None, *args, **kwargs):

            try:
                election = Election.get_by_uuid(uuid=election_uuid,)

                voter = Voter.get_by_login_id_and_election(
                    voter_login_id=user_session,
                    election_id=election.id,
                )

                if not verify_voter(election, voter):
                    raise HTTPException(status_code=401, detail="you do not have permissions to access this election")

            except:
                raise HTTPException(status_code = 401, detail = "an error occurred while verifying the voter")

            return await f(election, voter, *args, **kwargs)

        return update_wrapper(voter_cas_wrapper, f)

    return voter_cas_decorator


def trustee_cas(**kwargs):
    """
    Decorator to check if the trustee is registered in the election

    """

    def trustee_cas_decorator(f):
        async def trustee_cas_wrapper(
            user_session=None, election_uuid=None, trustee_uuid=None, *args, **kwargs
        ):
            try:
                election = Election.get_by_uuid(uuid=election_uuid)

                trustee = Trustee.get_by_login_id_and_election(
                    trustee_login_id=user_session,
                    election_id=election.id,
                )

                if not verify_trustee(election, trustee):
                    raise HTTPException(status_code = 401, detail = "you do not have permissions to access this election")

            except:
                raise HTTPException(status_code = 401, detail = "an error has occurred while obtaining the election data")

            return await f(election, trustee, *args, **kwargs)

        return update_wrapper(trustee_cas_wrapper, f)

    return trustee_cas_decorator


def create_user(username: str, password: str, db: Session = Depends(get_db)) -> str:
    """
    Create a new user
    :param username: username of the user
    :param password: password of the user


    """

    hashed_password = generate_password_hash(password, method="sha256")
    user = schemas.User(
        public_id=str(uuid.uuid4()),
        username=username,
        password=hashed_password
    )
    crud.create_user(
        db=db,
        user=user
    )
    logging.log(msg="User created successfully!", level=logging.INFO)

def verify_voter(election, voter):
    """
    Verify if the voter is registered in the election

    if the voter name finish with '@uchile.cl' it is verified
    that the user is found without the '@uchile.cl'

    :param voter_login_id: name of the voter
    :param election_uuid: uuid of the election

    """

    if not election:
        return False

    voter_login_id = voter.voter_login_id
    if not voter:
        if voter_login_id[-10:] == "@uchile.cl":
            voter = Voter.get_by_login_id_and_election(
                voter_login_id=voter_login_id[:-10],
                election_id=election.id,
            )
            if not voter:
                return False
        return False

    return True


def verify_trustee(election, trustee):
    """
    Verify if the trustee is registered in the election
    """

    if not election:
        return False

    trustee_login_id = trustee.trustee_login_id
    if not trustee:
        if trustee_login_id[-10:] == "@uchile.cl":
            trustee = Trustee.get_by_login_id_and_election(
                trustee_login_id=trustee_login_id[:-10],
                election_id=election.id,
            )
            if not trustee:
                return False
        return False

    return True


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
