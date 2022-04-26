from operator import and_
from sqlalchemy import true
from werkzeug.security import generate_password_hash
from functools import wraps
from flask import request, jsonify, session, redirect, make_response
from psifos import app, db
from psifos.psifos_auth.models import User
from psifos.models import Election, Voter
from psifos import config

import jwt
import uuid

from psifos.models import Voter


def token_required(f):
    """
    Decorator to check if the user is logged in

    """

    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = jwt.decode(
                token, app.config["SECRET_KEY"], algorithms=['HS256'])
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()
        except Exception as e:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args,  **kwargs)
    return decorator


def cas_requires(f: callable) -> callable:

    @wraps(f)
    def decorator(*args, **kwargs):
        if 'username' not in session:
            response = make_response({"message": "Usuario no autorizado"}, 401)
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response

        return f(*args, **kwargs)

    return decorator


def create_user(username: str, password: str) -> str:
    """
    Create a new user
    :param username: username of the user
    :param password: password of the user


    """

    hashed_password = generate_password_hash(password, method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), user_type="password",
                    user_id="admin", name=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return "Usuario creado"


def verify_voter(voter_name, election_uuid):
    """
    Verify if the voter is registered in the election

    if the voter name finish with '@uchile.cl' it is verified 
    that the user is found without the '@uchile.cl'

    :param voter_name: name of the voter
    :param election_uuid: uuid of the election

    """

    election = Election.query.filter_by(uuid=election_uuid).first()
    if not election:
        return False
    voter = Voter.query.filter_by(voter_name=voter_name, election=election.id).first()
    if not voter:
        if voter_name[-10:] == '@uchile.cl':
            voter  = Voter.query.filter_by(voter_name=voter_name[:-10], election=election.id).first()
            if not voter:
                return False
        return False

    return True

def create_response_cors(response):
    """
    Create a response with CORS headers

    :param response: response to be returned
    """
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response