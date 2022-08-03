import jwt
from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from psifos import app, config
from psifos.psifos_auth.auth_model import Auth, CASAuth
from psifos.psifos_auth.models import User
from werkzeug.security import check_password_hash

auth_factory = Auth()
protocol = config["AUTH"]["type_auth"]


@app.post("/login", status_code = 201)
def login_user(request: Request) -> Response:
    """
    Login a admin user

    """

    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return HTTPException(status_code = 401, detail="an error occurred, please try again")

    user = User.get_by_name(name=auth.username)

    if not user:
        return HTTPException(status_code = 401, detail = "wrong username or passwords")

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({"public_id": user.public_id}, app.config["SECRET_KEY"])
        return JSONResponse({"token": token})

    else:
        return HTTPException(status_code = 401, detail = "wrong username or passwords")


@app.route("/vote/<election_uuid>", methods=["GET", "POST"])
def login_voter(election_uuid: str) -> Response:
    """
    Make the connection and verification with the CAS service
    """

    auth = auth_factory.get_auth(protocol)
    return auth.login_voter(election_uuid)


@app.route("/vote/<election_uuid>/logout", methods=["GET"])
def logout_voter(election_uuid: str) -> Response:
    """
    Logout a user
    """

    auth = auth_factory.get_auth(protocol)
    return auth.logout_voter(election_uuid)


# Trustee Auth


@app.route("/<election_uuid>/trustee/login", methods=["GET", "POST"])
def login_trustee(election_uuid: str) -> Response:
    """
    Make the connection and verification with the CAS service
    """
    
    auth = auth_factory.get_auth(protocol)
    return auth.login_trustee(election_uuid)



@app.route("/<election_uuid>/trustee/logout", methods=["GET"])
def logout_trustee(election_uuid: str) -> Response:
    """
    Logout a trustee
    """
    auth = auth_factory.get_auth(protocol)
    return auth.logout_trustee(election_uuid)


# OAuth2


@app.route("/authorized")
def authorized():

    auth = auth_factory.get_auth(protocol)
    return auth.authorized()
