import jwt
from flask import make_response, request
from flask.wrappers import Response
from psifos import app, config
from psifos.psifos_auth.auth_model import Auth, CASAuth
from psifos.psifos_auth.models import User
from werkzeug.security import check_password_hash

auth_factory = Auth()
protocol = config["AUTH"]["type_auth"]


@app.route("/login", methods=["GET", "POST"])
def login_user() -> Response:
    """
    Login a admin user

    """

    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response({"message": "Ocurrio un error, intente nuevamente"}, 401)

    user = User.get_by_name(name=auth.username)

    if not user:
        return make_response({"message": "Usuario o contraseñas incorrectos"}, 401)

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({"public_id": user.public_id}, app.config["SECRET_KEY"])
        return make_response({"token": token}, 200)

    else:
        return make_response({"message": "Usuario o contraseñas incorrectos"}, 401)


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
