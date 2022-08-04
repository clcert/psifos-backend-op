import jwt
from werkzeug.security import check_password_hash
from fastapi import HTTPException, Request, Response, APIRouter, Depends

from app.dependencies import get_db
from app import config
from app.main import app

from app.psifos_auth.auth import Auth, CASAuth
from app.psifos_auth.model import crud

auth_factory = Auth()
protocol = config["AUTH"]["type_auth"]

auth_router = APIRouter()

@auth_router.post("/login", status_code = 201)
def login_user(request: Request, db = Depends(get_db)):
    """
    Login a admin user

    """

    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        raise HTTPException(status_code = 401, detail="an error occurred, please try again")

    user = crud.get_user_by_name(db=db, name=auth.username)

    if not user:
        raise HTTPException(status_code = 401, detail = "wrong username or passwords")

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({"public_id": user.public_id}, config["SECRET_KEY"])
        return {
            "token": token
        }

    else:
        raise HTTPException(status_code = 401, detail = "wrong username or passwords")


@auth_router.get("/vote/{election_uuid}", status_code=200)
def login_voter(election_uuid: str):
    """
    Make the connection and verification with the CAS service
    """

    auth = auth_factory.get_auth(protocol)
    return auth.login_voter(election_uuid)


@auth_router.route("/vote/<election_uuid>/logout", status_code=200)
def logout_voter(election_uuid: str):
    """
    Logout a user
    """

    auth = auth_factory.get_auth(protocol)
    return auth.logout_voter(election_uuid)


# Trustee Auth


@auth_router.get("/{election_uuid}/trustee/login", status_code=200)
def login_trustee(election_uuid: str):
    """
    Make the connection and verification with the CAS service
    """
    
    auth = auth_factory.get_auth(protocol)
    return auth.login_trustee(election_uuid)



@auth_router.route("/{election_uuid}/trustee/logout", status_code=200)
def logout_trustee(election_uuid: str):
    """
    Logout a trustee
    """
    auth = auth_factory.get_auth(protocol)
    return auth.logout_trustee(election_uuid)


# OAuth2


@auth_router.get("/authorized", status_code=200)
def authorized():

    auth = auth_factory.get_auth(protocol)
    return auth.authorized()
