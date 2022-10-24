from cas import CASClient
from app.database import SessionLocal
from app.config import APP_BACKEND_OP_URL, APP_FRONTEND_URL, CAS_URL, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_AUTHORIZE_URL, OAUTH_TOKEN_URL, OAUTH_USER_INFO_URL
from app.psifos.model import crud
from requests_oauthlib import OAuth2Session
from app.database import db_handler

from fastapi import Request, HTTPException
from starlette.responses import RedirectResponse
from app.logger import psifos_logger

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
    Class responsible for solving the logic
    of authentication with the CAS protocol
    """

    def __init__(self) -> None:
        self.cas_client = CASClient(
            version=3,
            service_url=APP_BACKEND_OP_URL + "/vote/",
            server_url=CAS_URL,
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
                url=APP_FRONTEND_URL + "/booth/" + election_uuid
            )
            response.set_cookie("session", session)
            return response

        # Get ticket from query string url
        ticket = request.query_params.get("ticket", None)

        # If no ticket, redirect to CAS server to get one (login)
        if not ticket:
            return self.redirect_cas(APP_BACKEND_OP_URL + election_uuid + "/vote")

        # Verify ticket with CAS server
        user, attributes, pgtiou = self.cas_client.verify_ticket(ticket)

        # If no user, return error
        if not user:
            raise HTTPException(status_code=401, detail="ERROR")

        # If user, set session and redirect to election page
        request.session["user"] = user
        response = RedirectResponse(
            url=APP_FRONTEND_URL + "/booth/" + election_uuid
        )
        return response

    def logout_voter(self, election_uuid: str, request: Request):

        # Get logoout url from CAS server
        cas_logout_url = self.cas_client.get_logout_url(
            APP_FRONTEND_URL + "/booth/" + election_uuid + "?logout=true"
        )

        # Clear cookie and redirect to election page
        response = RedirectResponse(url=cas_logout_url)
        request.session.clear()
        return response

    @db_handler.method_with_session
    async def login_trustee(self, db_session, election_uuid: str, request: Request, session: str):

        # Get user from session cookie
        user = request.session.get("user", None)

        if user:
            election = await crud.get_election_by_uuid(uuid=election_uuid, session=db_session)
            trustee = await crud.get_by_login_id_and_election_id(
                trustee_login_id=user,
                election_id=election.id,
                session=db_session
            )
            psifos_logger.trustee_info(name=user, trustee=trustee, election=election)
            if not trustee:
                response = RedirectResponse(
                    APP_FRONTEND_URL + f"/{election_uuid}/trustee/home"
                )
            else:

                response = RedirectResponse(
                    url=APP_FRONTEND_URL + f"/{election_uuid}/trustee/{trustee.uuid}/home"
                )
            response.set_cookie("session", session)
            return response

        ticket = request.query_params.get("ticket", None)
        if not ticket:
            return self.redirect_cas(
                APP_BACKEND_OP_URL + f"/{election_uuid}/trustee/login",
            )

        user, attributes, pgtiou = self.cas_client.verify_ticket(ticket)
        if not user:
            raise HTTPException(status_code=401, detail="ERROR")
        else:
            request.session["user"] = user
            election = await crud.get_election_by_uuid(uuid=election_uuid, session=db_session)
            trustee = await crud.get_by_login_id_and_election_id(
                session=db_session,
                trustee_login_id=request.session["user"],
                election_id=election.id,
            )
            psifos_logger.trustee_info(name=user, trustee=trustee, election=election)
            if not trustee:
                response = RedirectResponse(
                    url=APP_FRONTEND_URL + f"/{election_uuid}/trustee/home"
                )

            else:

                response = RedirectResponse(
                    APP_FRONTEND_URL + f"/{election_uuid}/trustee/{trustee.uuid}/home",
                )

            return response

    def logout_trustee(self, election_uuid: str, request: Request):

        cas_logout_url = self.cas_client.get_logout_url(
            APP_FRONTEND_URL + f"/{election_uuid}/trustee/home?logout=true"
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

        self.client_id = OAUTH_CLIENT_ID
        self.client_secret = OAUTH_CLIENT_SECRET
        self.scope = "openid"
        self.election_uuid = ""
        self.trustee_uuid = ""
        self.type_logout = ""

    def login_voter(self, election_uuid: str, request: Request = None, session: str = None):

        self.election_uuid = election_uuid
        self.type_logout = "voter"
        client = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=APP_BACKEND_OP_URL + "/authorized",
            scope=self.scope,
        )

        authorization_url, state = client.authorization_url(
            OAUTH_AUTHORIZE_URL
        )
        request.session["oauth_state"] = state
        return RedirectResponse(authorization_url)

    def logout_voter(self, election_uuid: str, request: Request):
        pass
        
    def login_trustee(self, election_uuid: str, request: Request, session: str):
        self.election_uuid = election_uuid
        self.type_logout = "trustee"
        client = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=APP_BACKEND_OP_URL + "/authorized",
            scope=self.scope,
        )

        authorization_url, state = client.authorization_url(
            OAUTH_AUTHORIZE_URL
        )
        request.session["oauth_state"] = state

        return RedirectResponse(authorization_url)

    def logout_trustee(self, election_uuid: str, request: Request):
        pass

    async def authorized(self, request: Request, session: str = None):
        login = OAuth2Session(
            self.client_id,
            state=request.session["oauth_state"],
            redirect_uri=APP_BACKEND_OP_URL + "/authorized",
        )
        resp = login.fetch_token(
            OAUTH_TOKEN_URL,
            client_secret=self.client_secret,
            authorization_response=str(request.url),
        )
        request.session["oauth_token"] = resp

        login = OAuth2Session(OAUTH_CLIENT_ID, token=request.session["oauth_token"])
        user = login.get(OAUTH_USER_INFO_URL).json()
        user = user["fields"]["username"]
        request.session["user"] = user
        
        async with SessionLocal() as session:
            election = crud.get_election_by_uuid(uuid=self.election_uuid, session=session)
            if self.type_logout == "voter":
                
                response = RedirectResponse(
                    APP_FRONTEND_URL + "/booth/" + self.election_uuid
                )
                # psifos_logger.voter_info(name=user, election=election)

            elif self.type_logout == "trustee":
                async with SessionLocal() as session:
                    election = await crud.get_election_by_uuid(uuid=self.election_uuid, session=session)
                    trustee = await crud.get_by_login_id_and_election_id(
                        trustee_login_id=user,
                        election_id=election.id,
                        session=session
                    )
                # psifos_logger.trustee_info(name=user, trustee=trustee, election=election)
                self.trustee_uuid = trustee.uuid if trustee else None

                if not self.trustee_uuid:
                    response = RedirectResponse(
                        APP_FRONTEND_URL
                        + "/"
                        + self.election_uuid
                        + "/trustee"
                        + "/home",
                    
                    )
                else:
                    response = RedirectResponse(
                        APP_FRONTEND_URL
                        + "/"
                        + self.election_uuid
                        + "/trustee/"
                        + self.trustee_uuid
                        + "/home",
                        
                    )

        return response