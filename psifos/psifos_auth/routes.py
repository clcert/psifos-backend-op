from psifos import app
from psifos import config
from psifos.models import Election, Trustee
from psifos.psifos_auth.auth_model import Auth, CASAuth
from psifos.psifos_auth.models import User
from psifos.psifos_auth.schemas import UserSchema
from psifos.routes import election_schema, trustee_schema

from psifos.psifos_auth.utils import cas_requires, verify_voter

from werkzeug.security import check_password_hash
from functools import wraps

from flask_cors import cross_origin
from flask.wrappers import Response
from flask import request, jsonify, make_response, redirect, session

import datetime
import jwt


auth_factory = Auth()


@app.route("/login", methods=["GET", "POST"])
def login_user() -> Response:
    """
    Login a admin user

    """

    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response({"message": "Ocurrio un error, intente nuevamente"}, 401)

    user_schema = UserSchema()
    user = User.get_by_name(schema=user_schema, name=auth.username)

    if not user:
        return make_response({"message": "Usuario o contraseñas incorrectos"}, 401)

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({"public_id": user.public_id}, app.config["SECRET_KEY"])
        return make_response({"token": token}, 200)

    else:
        return make_response({"message": "Usuario o contraseñas incorrectos"}, 401)


@app.route("/vote/<election_uuid>", methods=["GET", "POST"])
def cas_login(election_uuid: str) -> Response:
    """
    Make the connection and verification with the CAS service
    """

    auth = auth_factory.get_auth()
    return auth.login_voter(election_uuid)


@app.route("/vote/<election_uuid>/logout", methods=["GET"])
def logout(election_uuid: str) -> Response:
    """
    Logout a user
    """

    auth = auth_factory.get_auth()
    return auth.logout_voter(election_uuid)


# Trustee Auth


@app.route("/<election_uuid>/trustee/login", methods=["GET", "POST"])
def cas_login_trustee(election_uuid: str) -> Response:
    """
    Make the connection and verification with the CAS service
    """

    auth = auth_factory.get_auth()
    return auth.login_trustee(election_uuid, election_schema, trustee_schema)


@app.route("/<election_uuid>/trustee/logout", methods=["GET"])
def logout_trustee(election_uuid: str) -> Response:
    """
    Logout a trustee
    """
    auth = auth_factory.get_auth()
    return auth.logout_trustee(election_uuid)
