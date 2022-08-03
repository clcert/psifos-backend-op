import jwt
import uuid

from psifos import config
from werkzeug.security import generate_password_hash
from functools import update_wrapper, wraps
from fastapi import HTTPException, Request
from psifos import app, db
from requests_oauthlib import OAuth2Session
from psifos.psifos_auth.models import User
from psifos.database.models import Election, Trustee, Voter
from psifos.database.models import Voter


def token_required(f):
    """
    Decorator to check if the user is logged in

    """

    @wraps(f)
    async def decorator(request: Request, *args, **kwargs):
        token = None
        if "x-access-tokens" in request.headers:
            token = request.headers["x-access-tokens"]

        if not token:
            raise HTTPException(status_code=401, detail="a valid token is missing")

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = User.get_by_public_id(public_id=data["public_id"])

        except Exception as e:
            raise HTTPException(status_code=401, detail="token is invalid")

        return await f(current_user, *args, **kwargs)

    return decorator


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


def create_response_cors(response):
    """
    Create a response with CORS headers

    :param response: response to be returned
    """
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,PUT,POST,DELETE,OPTIONS"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


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
