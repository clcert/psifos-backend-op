from urllib import response
from cas import CASClient
from app.config import env
from ..database import SessionLocal
from app.psifos.model.models import Election, Trustee
from app.psifos.model import crud
from requests_oauthlib import OAuth2Session

from fastapi import Request, HTTPException
from starlette.responses import RedirectResponse

class Auth:

    """
    Class in charge of storing all the authentication
    protocols and discriminating which one to use

    """

    def __init__(self) -> None:
        self.cas = CASAuth()
        self.oauth = OAuth2Auth()

    def get_auth(self, type_auth: str = "cas") -> object:
        """
        Returns an instance of Auth.
        """

        if type_auth == "cas":
            return self.cas
        elif type_auth == "oauth":
            return self.oauth


class CASAuth:

    """
    Class responsible for solving the logic of
    authentication with the CAS protocol

    """

    def __init__(self) -> None:
        self.cas_client = CASClient(
            version=3,
            service_url=env["URL"]["back"] + "/vote/",
            server_url=env["CAS"]["cas_url"],
        )

    def redirect_cas(self, redirect_url):
        """
        Redirects to the CAS server

        """

        self.cas_client.service_url = redirect_url
        cas_login_url = self.cas_client.get_login_url()
        return RedirectResponse(url=cas_login_url)

    def login_voter(self, election_uuid: str, request: Request = None, session: str = None):
        """
        Login a voter
        """

        # Get user from session cookie
        user = request.session.get("user", None)
        if user:

            response = RedirectResponse(
                url=env["URL"]["front"] + "/cabina/" + election_uuid
            )
            response.set_cookie("session", session)
            return response

        # Get ticket from query string url
        ticket = request.query_params.get("ticket", None)

        # If no ticket, redirect to CAS server to get one (login)
        if not ticket:
            return self.redirect_cas(env["URL"]["back"] + "/vote/" + election_uuid)

        # Verify ticket with CAS server
        user, attributes, pgtiou = self.cas_client.verify_ticket(ticket)

        # If no user, return error
        if not user:
            raise HTTPException(status_code=401, detail="ERROR")

        # If user, set session and redirect to election page
        request.session["user"] = user
        response = RedirectResponse(
            url=env["URL"]["front"] + "/cabina/" + election_uuid
        )
        return response

    def logout_voter(self, election_uuid: str, request: Request):

        # Get logoout url from CAS server
        cas_logout_url = self.cas_client.get_logout_url(
            env["URL"]["front"] + "/cabina/" + election_uuid + "?logout=true"
        )

        # Clear cookie and redirect to election page
        response = RedirectResponse(url=cas_logout_url)
        request.session.clear()
        return response

    def login_trustee(self, election_uuid: str, request: Request, session: str):

        # Get user from session cookie
        user = request.session.get("user", None)

        with SessionLocal() as db:
            if user:
                election = crud.get_election_by_uuid(uuid=election_uuid, db=db)
                trustee = crud.get_by_login_id_and_election_id(
                    trustee_login_id=user,
                    election_id=election.id,
                    db=db
                )
                if not trustee:
                    response = RedirectResponse(
                        env["URL"]["front"] + "/" + election_uuid + "/trustee" + "/home"
                    )
                else:

                    response = RedirectResponse(
                        url=env["URL"]["front"]
                        + "/"
                        + election_uuid
                        + "/trustee/"
                        + trustee.uuid
                        + "/home"
                    )
                response.set_cookie("session", session)
                return response

            ticket = request.query_params.get("ticket", None)
            if not ticket:
                return self.redirect_cas(
                    env["URL"]["back"] + "/" + election_uuid + "/trustee" + "/login",
                )

            user, attributes, pgtiou = self.cas_client.verify_ticket(ticket)
            if not user:
                raise HTTPException(status_code=401, detail="ERROR")
            else:
                request.session["user"] = user
                election = crud.get_election_by_uuid(uuid=election_uuid, db=db)
                trustee = crud.get_by_login_id_and_election_id(
                    db=db,
                    trustee_login_id=request.session["user"],
                    election_id=election.id,
                )
                if not trustee:
                    response = RedirectResponse(
                        url=env["URL"]["front"] + "/" + election_uuid + "/trustee" + "/home"
                    )
                else:

                    response = RedirectResponse(
                        env["URL"]["front"]
                        + "/"
                        + election_uuid
                        + "/trustee/"
                        + trustee.uuid
                        + "/home",
                    
                    )
                return response

    def logout_trustee(self, election_uuid: str, request: Request):

        cas_logout_url = self.cas_client.get_logout_url(
            env["URL"]["front"]
            + "/"
            + election_uuid
            + "/trustee"
            + "/home"
            + "?logout=true"
        )

        response = RedirectResponse(url=cas_logout_url)
        request.session.clear()
        return response


class OAuth2Auth:
    def __init__(self) -> None:
        """
        Class responsible for solving the logic of
        authentication with the OAUTH2 protocol

        """

        self.client_id = env["OAUTH"]["client_id"]
        self.client_secret = env["OAUTH"]["client_secret"]
        self.scope = "openid"
        self.election_uuid = ""
        self.trustee_uuid = ""
        self.type_logout = ""

    def login_voter(self, election_uuid: str, request: Request = None, session: str = None):

        self.election_uuid = election_uuid
        self.type_logout = "voter"
        client = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=env["URL"]["back"] + "/authorized",
            scope=self.scope,
        )

        authorization_url, state = client.authorization_url(
            env["OAUTH"]["authorize_url"]
        )
        request.session["oauth_state"] = state
        return RedirectResponse(authorization_url)

    def logout_voter(self, election_uuid: str, request: Request):

        client = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=env["URL"]["back"] + "/authorized",
            scope=self.scope,
        )
        authorization_url, state = client.authorization_url(
            env["OAUTH"]["authorize_url"]
        )
        request.session.clear()
        response = RedirectResponse(authorization_url)
        

    def login_trustee(self, election_uuid: str, request: Request, session: str):

        self.election_uuid = election_uuid
        self.type_logout = "trustee"
        client = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=env["URL"]["back"] + "/authorized",
            scope=self.scope,
        )

        authorization_url, state = client.authorization_url(
            env["OAUTH"]["authorize_url"]
        )
        request.session["oauth_state"] = state

        return RedirectResponse(authorization_url)

    def logout_trustee(self, election_uuid: str, request: Request):
        
        client = OAuth2Session(
            client_id=self.client_id,
            scope=self.scope,
        )
        authorization_url, state = client.authorization_url(
            env["OAUTH"]["authorize_url"]
        )
        request.session["oauth_state"] = state
        request.session.clear()
        response = RedirectResponse(authorization_url)
        response.set_cookie("session", None)
        return response

    def authorized(self, request: Request, session: str = None):
        login = OAuth2Session(
            self.client_id,
            state=request.session["oauth_state"],
            redirect_uri=env["URL"]["back"] + "/authorized",
        )
        resp = login.fetch_token(
            env["OAUTH"]["token_url"],
            client_secret=self.client_secret,
            authorization_response=str(request.url),
        )
        request.session["oauth_token"] = resp

        login = OAuth2Session(env["OAUTH"]["client_id"], token=request.session["oauth_token"])
        user = login.get(env["OAUTH"]["user_info_url"]).json()
        user = user["fields"]["username"]
        request.session["user"] = user

        if self.type_logout == "voter":
            response = RedirectResponse(
                env["URL"]["front"] + "/cabina/" + self.election_uuid
            )

        elif self.type_logout == "trustee":

            with SessionLocal() as db:

                election = crud.get_election_by_uuid(uuid=self.election_uuid, db=db)
                trustee = crud.get_by_login_id_and_election_id(
                    trustee_login_id=user,
                    election_id=election.id,
                    db=db
                )
                self.trustee_uuid = trustee.uuid if trustee else None

                if not self.trustee_uuid:
                    response = RedirectResponse(
                        env["URL"]["front"]
                        + "/"
                        + self.election_uuid
                        + "/trustee"
                        + "/home",
                    
                    )
                else:
                    response = RedirectResponse(
                        env["URL"]["front"]
                        + "/"
                        + self.election_uuid
                        + "/trustee/"
                        + self.trustee_uuid
                        + "/home",
                        
                    )

        return response