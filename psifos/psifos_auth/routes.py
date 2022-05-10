from psifos import app
from psifos import config
from psifos import cas_client
from psifos.models import Trustee
from psifos.psifos_auth.models import User
from psifos.psifos_auth.schemas import UserSchema

from psifos.psifos_auth.utils import cas_requires, verify_voter

from werkzeug.security import check_password_hash
from functools import wraps

from flask_cors import cross_origin
from flask.wrappers import Response
from flask import request, jsonify, make_response, redirect, session

import datetime
import jwt

from psifos.schemas import TrusteeSchema


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


def redirect_cas(election_uuid: str) -> Response:
    cas_client.service_url = config["URL"]["back"] + "/vote/" + election_uuid
    cas_login_url = cas_client.get_login_url()
    return redirect(cas_login_url)


@app.route("/vote/<election_uuid>", methods=["GET", "POST"])
def cas_login(election_uuid: str) -> Response:
    """
    Make the connection and verification with the CAS service
    """

    cookie = request.cookies.get("session")
    if "username" in session:

        # Already logged in
        response = redirect(
            config["URL"]["front"] + "/cabina/" + election_uuid, code=302
        )
        response.set_cookie("session", cookie)
        return response

    ticket = request.args.get("ticket")
    if not ticket:
        # No ticket, the request come from end user, send to CAS login
        return redirect_cas(election_uuid)

    user, attributes, pgtiou = cas_client.verify_ticket(ticket)
    if not user:
        return make_response({"message": "ERROR"}, 401)
    else:  # Login successfully, redirect according `next` query parameter.
        session["username"] = user
        response = redirect(
            config["URL"]["front"] + "/cabina/" + election_uuid, code=302
        )
        return response


@app.route("/vote/<election_uuid>/logout", methods=["GET"])
def logout(election_uuid: str) -> Response:
    """
    Logout a user
    """
    cas_logout_url = cas_client.get_logout_url(
        config["URL"]["front"] + "/cabina/" + election_uuid + "?logout=true"
    )

    response = redirect(cas_logout_url, code=302)
    response.set_cookie("session", expires=0)
    return response


@cross_origin
@app.route("/election_questions/<election_uuid>", methods=["GET"])
@cas_requires
def get_election_cas(election_uuid: str) -> Response:
    if not verify_voter(session["username"], election_uuid):
        response = make_response({"message": "Votante no esta en la elección"}, 401)
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response

    response = make_response(jsonify({"message": "Autorizado"}), 200)
    response.headers["Access-Control-Allow-Credentials"] = "true"

    return response


# Trustee CAS

def redirect_cas_trustee(election_uuid: str) -> Response:
    cas_client.service_url = (
        config["URL"]["back"] + "/" + election_uuid + "/trustee" + "/login"
    )
    cas_login_url = cas_client.get_login_url()
    return redirect(cas_login_url)


@app.route("/<election_uuid>/trustee/login", methods=["GET", "POST"])
def cas_login_trustee(election_uuid: str) -> Response:
    """
    Make the connection and verification with the CAS service
    """

    cookie = request.cookies.get("session")
    trustee_schema = TrusteeSchema()

    if "username" in session:
        # Already logged in
        trustee_uuid = Trustee.filter_by(
            schema=trustee_schema, trustee_login_id=session["username"]
        )[0].uuid
        response = redirect(
            config["URL"]["front"]
            + "/"
            + election_uuid
            + "/trustee/"
            + trustee_uuid
            + "/home",
            code=302,
        )
        response.set_cookie("session", cookie)
        return response

    ticket = request.args.get("ticket")
    if not ticket:
        # No ticket, the request come from end user, send to CAS login
        return redirect_cas_trustee(election_uuid)

    user, attributes, pgtiou = cas_client.verify_ticket(ticket)
    if not user:
        return make_response({"message": "ERROR"}, 401)
    else:  # Login successfully, redirect according `next` query parameter.
        session["username"] = user
        trustee_uuid = Trustee.filter_by(
            schema=trustee_schema, trustee_login_id=session["username"]
        )[0].uuid
        response = redirect(
            config["URL"]["front"]
            + "/"
            + election_uuid
            + "/trustee/"
            + trustee_uuid
            + "/home",
            code=302,
        )
        return response


@app.route("/<election_uuid>/trustee/<trustee_uuid>/logout", methods=["GET"])
def logout_trustee(election_uuid: str, trustee_uuid: str) -> Response:
    """
    Logout a trustee
    """
    cas_logout_url = cas_client.get_logout_url(
        config["URL"]["front"]
        + "/"
        + election_uuid
        + "/trustee/"
        + trustee_uuid
        + "/home"
        + "?logout=true"
    )

    response = redirect(cas_logout_url, code=302)
    response.set_cookie("session", expires=0)
    return response
