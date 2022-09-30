import jwt
from werkzeug.security import check_password_hash
from fastapi import HTTPException, Request, APIRouter, Depends, Cookie

from app.dependencies import get_db
from app.config import SECRET_KEY, TYPE_AUTH

from app.psifos_auth.auth_service_log import Auth
from app.psifos_auth.model import crud

from fastapi.security import HTTPBasic, HTTPBasicCredentials

auth_factory = Auth()
protocol = TYPE_AUTH

auth_router = APIRouter(prefix="/psifos/api/app")

security = HTTPBasic()

@auth_router.post("/login", status_code = 201)
def login_user(request: Request, credentials: HTTPBasicCredentials = Depends(security), db = Depends(get_db)):
    """
    Login a admin user

    """

    if not credentials or not credentials.username or not credentials.password:
        raise HTTPException(status_code = 401, detail="an error occurred, please try again")

    user = crud.get_user_by_name(db=db, name=credentials.username)

    if not user:
        raise HTTPException(status_code = 401, detail = "wrong username or passwords")

    if check_password_hash(user.password, credentials.password):
        token = jwt.encode({"public_id": user.public_id}, SECRET_KEY)
        return {
            "token": token
        }

    else:
        raise HTTPException(status_code = 401, detail = "wrong username or passwords")


@auth_router.get("/vote/{election_uuid}", status_code=200)
def login_voter(election_uuid: str, request: Request, session: str | None = Cookie(default=None)):
    """
    Make the connection and verification with the CAS service
    """

    auth = auth_factory.get_auth(protocol)
    return auth.login_voter(election_uuid, request=request, session=session)


@auth_router.get("/vote/{election_uuid}/logout", status_code=200)
def logout_voter(election_uuid: str, request: Request):
    """
    Logout a user
    """

    auth = auth_factory.get_auth(protocol)
    return auth.logout_voter(election_uuid, request)


# Trustee Auth


@auth_router.get("/{election_uuid}/trustee/login", status_code=200)
def login_trustee(election_uuid: str, request: Request, session: str | None = Cookie(default=None)):
    """
    Make the connection and verification with the CAS service
    """
    
    auth = auth_factory.get_auth(protocol)
    return auth.login_trustee(election_uuid, request=request, session=session)



@auth_router.get("/{election_uuid}/trustee/logout", status_code=200)
def logout_trustee(election_uuid: str, request: Request):
    """
    Logout a trustee
    """
    auth = auth_factory.get_auth(protocol)
    return auth.logout_trustee(election_uuid, request)


# OAuth2


@auth_router.get("/authorized", status_code=200)
def authorized(request: Request, session: str | None = Cookie(default=None)):

    auth = auth_factory.get_auth(protocol)
    return auth.authorized(request, session=session)
