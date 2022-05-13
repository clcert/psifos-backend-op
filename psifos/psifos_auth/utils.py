from operator import and_
from os import abort
from subprocess import call
from sqlalchemy import true
from werkzeug.security import generate_password_hash
from functools import update_wrapper, wraps
from flask import request, jsonify, session, redirect, make_response
from psifos import app, db
from psifos.psifos_auth.models import User
from psifos.psifos_auth.schemas import UserSchema
from psifos.models import Election, Trustee, Voter
from psifos import config

import jwt
import uuid

from psifos.models import Voter
from psifos.schemas import ElectionSchema, TrusteeSchema, VoterSchema


def token_required(f):
    """
    Decorator to check if the user is logged in

    """

    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if "x-access-tokens" in request.headers:
            token = request.headers["x-access-tokens"]

        if not token:
            return jsonify({"message": "a valid token is missing"})

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            user_schema = UserSchema()
            current_user = User.get_by_public_id(
                schema=user_schema, public_id=data["public_id"]
            )

        except Exception as e:
            return make_response(jsonify({"message": "token is invalid"}), 401)

        return f(current_user, *args, **kwargs)

    return decorator


def election_route(**kwargs):

    """
    Decorator to check if the election is an admin election

    """

    election_schema = kwargs.get("election_schema", None)
    admin_election = kwargs.get("admin_election", True)
    deserialize_election = kwargs.get("deserialize_election", False)

    def election_route_decorator(f):
        def election_route_wrapper(
            current_user=None, election_uuid=None, *args, **kwargs
        ):
            election = Election.get_by_uuid(
                schema=election_schema,
                uuid=election_uuid,
                deserialize=deserialize_election,
            )
            if not election:
                return jsonify({"message": "election not found"})
            if admin_election and election.admin_id != current_user.id:
                return jsonify({"message": "election is not an admin election"})

            return f(election, *args, **kwargs)

        return update_wrapper(election_route_wrapper, f)

    return election_route_decorator


def cas_requires(f: callable) -> callable:
    @wraps(f)
    def decorator(*args, **kwargs):

        user_session = session.get("username", None)
        if not user_session:
            response = make_response({"message": "Usuario no autorizado"}, 401)
            response.headers["Access-Control-Allow-Credentials"] = "true"
            return response

        return f(user_session, *args, **kwargs)

    return decorator


def voter_cas(**kwargs):

    """
    Decorator to check if the voter is registered in the election

    """

    election_schema = kwargs.get("election_schema", None)
    voter_schema = kwargs.get("voter_schema", None)

    def voter_cas_decorator(f):
        def voter_cas_wrapper(user_session=None, election_uuid=None, *args, **kwargs):
            election = Election.get_by_uuid(
                schema=election_schema,
                uuid=election_uuid,
                deserialize=False,
            )

            voter = Voter.get_by_login_id_and_election(
                schema=voter_schema,
                voter_login_id=user_session,
                election_id=election.id,
            )

            if not verify_voter(election, voter, voter_schema):
                response = create_response_cors(
                    make_response(
                        jsonify(
                            {
                                "message": "No tiene permisos para acceder a esta elección"
                            }
                        ),
                        401,
                    )
                )
                return response

            return f(election, voter, *args, **kwargs)

        return update_wrapper(voter_cas_wrapper, f)

    return voter_cas_decorator


def trustee_cas(**kwargs):

    """
    Decorator to check if the trustee is registered in the election

    """

    election_schema = kwargs.get("election_schema", None)
    trustee_schema = kwargs.get("trustee_schema", None)

    def trustee_cas_decorator(f):
        def trustee_cas_wrapper(
            user_session=None, election_uuid=None, trustee_uuid=None, *args, **kwargs
        ):
            election = Election.get_by_uuid(
                schema=election_schema,
                uuid=election_uuid,
                deserialize=False,
            )

            trustee = Trustee.get_by_login_id_and_election(
                schema=trustee_schema,
                trustee_login_id=user_session,
                election_id=election.id,
            )

            if not verify_trustee(election, trustee, trustee_schema):
                response = create_response_cors(
                    make_response(
                        jsonify(
                            {
                                "message": "No tiene permisos para acceder a esta elección"
                            }
                        ),
                        401,
                    )
                )
                return response

            return f(election, trustee, *args, **kwargs)

        return update_wrapper(trustee_cas_wrapper, f)

    return trustee_cas_decorator


def create_user(username: str, password: str) -> str:
    """
    Create a new user
    :param username: username of the user
    :param password: password of the user


    """

    hashed_password = generate_password_hash(password, method="sha256")

    new_user = User(
        public_id=str(uuid.uuid4()),
        user_type="password",
        user_id="admin",
        name=username,
        password=hashed_password,
    )
    db.session.add(new_user)
    db.session.commit()

    return "Usuario creado"


def verify_voter(election, voter, voter_schema):
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
                schema=voter_schema,
                voter_login_id=voter_login_id[:-10],
                election_id=election.id,
            )
            if not voter:
                return False
        return False

    return True


def verify_trustee(election, trustee, trustee_schema):
    """
    Verify if the trustee is registered in the election
    """

    if not election:
        return False

    trustee_login_id = trustee.trustee_login_id
    if not trustee:
        if trustee_login_id[-10:] == "@uchile.cl":
            trustee = Trustee.get_by_login_id_and_election(
                schema=trustee_schema,
                trustee_login_id=trustee_login_id[:-10],
                election_id=election.id,
            )
            if not trustee:
                return False
        return False

    return True


def create_response_cors(response):
    """
    Create a response with CORS headers

    :param response: response to be returned
    """
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,PUT,POST,DELETE,OPTIONS"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response
