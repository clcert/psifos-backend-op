import jwt
import uuid

from werkzeug.security import check_password_hash
from fastapi import HTTPException, Request, APIRouter, Depends, Cookie, Query

from app.dependencies import get_session
from app.config import SECRET_KEY, TYPE_AUTH, APP_FRONTEND_URL

from app.psifos_auth.auth_service_logging import AuthFactory
from app.psifos_auth.model import crud as auth_crud
from app.psifos.model.cruds import crud
from app.psifos.model import models
from app.psifos.model.enums import ElectionLoginTypeEnum

from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.responses import RedirectResponse

auth_factory = AuthFactory()
protocol = TYPE_AUTH

# auth_router = APIRouter(prefix="/psifos/api/app")
auth_router = APIRouter()

security = HTTPBasic()

@auth_router.post("/login", status_code = 201)
async def login_user(request: Request, credentials: HTTPBasicCredentials = Depends(security), session = Depends(get_session)):
    """
    Login a admin user

    """

    if not credentials or not credentials.username or not credentials.password:
        raise HTTPException(status_code = 401, detail="an error occurred, please try again")    

    user = await auth_crud.get_user_by_name(session=session, name=credentials.username)

    if not user:
        raise HTTPException(status_code = 401, detail = "wrong username or passwords")

    if check_password_hash(user.password, credentials.password):
        token = jwt.encode({"public_id": user.public_id}, SECRET_KEY)
        return {
            "token": token
        }

    else:
        raise HTTPException(status_code = 401, detail = "wrong username or passwords")


@auth_router.get("/{short_name}/vote", status_code=200)
async def login_voter(short_name: str, request: Request, redirect: bool = Query(True), session_cookie: str | None = Cookie(default=None), session = Depends(get_session)):
    """
    Make the connection and verification with the CAS service
    """
    
    query_params = [
        models.Election.election_login_type,
    ]

    election = await crud.get_election_params_by_name(session=session, short_name=short_name, params=query_params)
    if not election:
        return RedirectResponse(url=APP_FRONTEND_URL + "psifos/booth/" + short_name) if redirect else {"message": "success"}

    if election.election_login_type == ElectionLoginTypeEnum.open_p:
        request.session["public_election"] = True
        request.session["user"] = str(uuid.uuid4())
        return RedirectResponse(url=APP_FRONTEND_URL + "psifos/booth/" + short_name) if redirect else {"message": "success"}

    auth = auth_factory.get_auth(protocol)
    return await auth.login_voter(short_name=short_name, request=request, session=session_cookie)


@auth_router.get("/vote/{short_name}/logout", status_code=200)
async def logout_voter(short_name: str, request: Request):
    """
    Logout a user
    """

    auth = auth_factory.get_auth(protocol)
    return auth.logout_voter(short_name, request)


# Trustee Auth


@auth_router.get("/{short_name}/trustee/login", status_code=200)
async def login_trustee(short_name: str, request: Request, session_cookie: str | None = Cookie(default=None)):
    """
    Make the connection and verification with the CAS service
    """
    
    auth = auth_factory.get_auth(protocol)
    return await auth.login_trustee(short_name=short_name, request=request, session=session_cookie)



@auth_router.get("/{short_name}/trustee/logout", status_code=200)
async def logout_trustee(short_name: str, request: Request):
    """
    Logout a trustee
    """
    auth = auth_factory.get_auth(protocol)
    return auth.logout_trustee(short_name, request)


# OAuth2


@auth_router.get("/authorized", status_code=200)
async def authorized(request: Request, session_cookie: str | None = Cookie(default=None)):

    auth = auth_factory.get_auth(protocol)
    return await auth.authorized(request, session=session_cookie)
