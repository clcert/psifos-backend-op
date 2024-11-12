from cas import CASClient
from app.database import SessionLocal
from app.config import (
    APP_BACKEND_OP_URL,
    APP_FRONTEND_URL,
    CAS_URL,
    OAUTH_CLIENT_ID,
    OAUTH_CLIENT_SECRET,
    OAUTH_AUTHORIZE_URL,
    OAUTH_TOKEN_URL,
    OAUTH_USER_INFO_URL,
    OAUTH_GOOGLE,
)
from app.psifos.model.cruds import crud
from requests_oauthlib import OAuth2Session
from app.database import db_handler

from fastapi import Request, HTTPException
from starlette.responses import RedirectResponse
from app.logger import psifos_logger, logger
from app.psifos.model.enums import ElectionAdminEventEnum, ElectionLoginTypeEnum


class AuthFactory:
    @staticmethod
    def get_auth(type_auth: str = "cas") -> object:
        """
        Returns an instance of Auth.
        """

        if type_auth == "cas":
            return CASAuth()
        elif type_auth == "oauth":
            return OAuth2Auth()


class AbstractAuth(object):

    """
    Class in charge of storing all the authentication
    protocols and discriminating which one to use

    """

    async def check_trustee(self, db_session, short_name: str, request: Request):
        """
        Check if the trustee that logs in exists and redirects
        """

        election = await crud.get_election_by_short_name(
            short_name=short_name, session=db_session
        )
        if not election:
            return RedirectResponse(
                url=APP_FRONTEND_URL + f"psifos/{short_name}/trustee/home"
            )

        trustee = await crud.get_by_login_id_and_election_id(
            session=db_session,
            trustee_login_id=request.session["user"],
            election_id=election.id,
        )
        if not trustee:
            logger.error("%s - Invalid Trustee Access: %s (%s)" % (request.client.host, request.session["user"], short_name))
            await psifos_logger.warning(
                election_id=election.id,
                event=ElectionAdminEventEnum.TRUSTEE_LOGIN_FAIL,
                user=request.session["user"],
            )
            return RedirectResponse(
                url=APP_FRONTEND_URL + f"psifos/{short_name}/trustee/home"
            )
        else:
            logger.log("PSIFOS", "%s - Valid Trustee Access: %s (%s)" % (request.client.host, request.session["user"], short_name))
            await psifos_logger.info(
                election_id=election.id,
                event=ElectionAdminEventEnum.TRUSTEE_LOGIN,
                user=request.session["user"],
            )
            return RedirectResponse(
                APP_FRONTEND_URL + f"psifos/{short_name}/trustee/{trustee.uuid}/home",
            )

    async def check_voter(self, db_session, short_name: str, user_id: str):
        """
        Check if the voter that logs in exists and redirects
        """

        query_params = [
            crud.models.Election.id,
            crud.models.Election.election_login_type,
        ]

        election = await crud.get_election_params_by_name(
            session=db_session, short_name=short_name, params=query_params
        )
        voter = await crud.get_voter_by_login_id_and_election_id(
            db_session, user_id, election.id
        )

        if (voter is not None) or (
            not election.election_login_type == ElectionLoginTypeEnum.close_p
        ):
            await psifos_logger.info(
                election_id=election.id,
                event=ElectionAdminEventEnum.VOTER_LOGIN,
                user=user_id,
            )

        else:
            await psifos_logger.info(
                election_id=election.id,
                event=ElectionAdminEventEnum.VOTER_LOGIN_FAIL,
                user=user_id,
            )

        return RedirectResponse(url=APP_FRONTEND_URL + "psifos/booth/" + short_name)


class CASAuth(AbstractAuth):
    """
    Class responsible for solving the logic
    of authentication with the CAS protocol
    """

    def __init__(self) -> None:
        self.cas_client = CASClient(
            version=3,
            service_url=APP_BACKEND_OP_URL + "vote/",
            server_url=CAS_URL,
        )

    def redirect_cas(self):
        """
        Redirects to the CAS server

        """
        cas_login_url = self.cas_client.get_login_url()
        return RedirectResponse(url=cas_login_url)

    @db_handler.method_with_session
    async def login_voter(
        self, db_session, short_name: str, request: Request = None, session: str = None
    ):
        """
        Voter login by CAS method
        """

        # Get user from session cookie
        user = request.session.get("user", None)

        if user:
            response = await self.check_voter(db_session, short_name, user)
            response.set_cookie("session", session)
            return response

        # Get ticket from query string url
        ticket = request.query_params.get("ticket", None)
        self.cas_client.service_url = APP_BACKEND_OP_URL + short_name + "/vote"

        # If no ticket, redirect to CAS server to get one (login)
        if not ticket:
            return self.redirect_cas()

        # Verify ticket with CAS server
        user, attributes, pgtiou = self.cas_client.verify_ticket(ticket)

        # If no user, return error

        if not user:
            raise HTTPException(status_code=401, detail="ERROR")

        # If user, set session and redirect to election page
        request.session["user"] = user
        return await self.check_voter(db_session, short_name, user)

    def logout_voter(self, short_name: str, request: Request):
        """
        Voter logout by CAS method
        """

        # Get logoout url from CAS server
        cas_logout_url = self.cas_client.get_logout_url(
            APP_FRONTEND_URL + "psifos/booth/" + short_name + "?logout=true"
        )

        # Clear cookie and redirect to election page
        response = RedirectResponse(url=cas_logout_url)
        request.session.clear()
        return response

    @db_handler.method_with_session
    async def login_trustee(
        self, db_session, short_name: str, request: Request, session: str
    ):
        """
        Trustee login by CAS method
        """

        # Get user from session cookie
        user = request.session.get("user", None)

        if user:
            response = await self.check_trustee(db_session, short_name, request)
            response.set_cookie("session", session)
            return response

        ticket = request.query_params.get("ticket", None)
        self.cas_client.service_url = APP_BACKEND_OP_URL + f"{short_name}/trustee/login"

        if not ticket:
            return self.redirect_cas()

        user, attributes, pgtiou = self.cas_client.verify_ticket(ticket)
        if not user:
            raise HTTPException(status_code=401, detail="ERROR")
        else:
            request.session["user"] = user
            return await self.check_trustee(db_session, short_name, request)

    def logout_trustee(self, short_name: str, request: Request):
        """
        Trustee logout by CAS method
        """

        cas_logout_url = self.cas_client.get_logout_url(
            APP_FRONTEND_URL + f"psifos/{short_name}/trustee/home?logout=true"
        )

        response = RedirectResponse(url=cas_logout_url)
        request.session.clear()
        return response


class OAuth2Auth(AbstractAuth):
    def __init__(self) -> None:
        """
        Class responsible for solving the logic of
        authentication with the OAUTH2 protocol

        """
        self.client_id = OAUTH_CLIENT_ID
        self.client_secret = OAUTH_CLIENT_SECRET
        self.scope = (
            "openid"
            if not OAUTH_GOOGLE
            else [
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile",
            ]
        )
        self.short_name = ""
        self.type_logout = ""

    @db_handler.method_with_session
    async def login_voter(
        self, db_session, short_name: str, request: Request = None, session: str = None
    ):
        request.session["short_name"] = short_name
        request.session["type_logout"] = "voter"
        client = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=APP_BACKEND_OP_URL + "authorized",
            scope=self.scope,
        )

        authorization_url, state = client.authorization_url(OAUTH_AUTHORIZE_URL)
        request.session["oauth_state"] = state
        return RedirectResponse(authorization_url)

    def logout_voter(self, short_name: str, request: Request):
        pass

    @db_handler.method_with_session
    async def login_trustee(
        self, db_session, request: Request, session: str, panel: bool = False, short_name: str = None
    ):
        request.session["short_name"] = short_name
        request.session["type_logout"] = "trustee"
        request.session["panel"] = panel

        self.type_logout = "trustee"
        client = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=APP_BACKEND_OP_URL + "authorized",
            scope=self.scope,
        )

        authorization_url, state = client.authorization_url(OAUTH_AUTHORIZE_URL)
        request.session["oauth_state"] = state

        return RedirectResponse(authorization_url)

    def logout_trustee(self, short_name: str, request: Request):
        pass

    @db_handler.method_with_session
    async def authorized(self, db_session, request: Request, session: str = None):
        short_name = request.session["short_name"]
        isPanel = request.session.get("panel", False)
        login = OAuth2Session(
            self.client_id,
            state=request.session["oauth_state"],
            redirect_uri=APP_BACKEND_OP_URL + "authorized",
        )
        resp = login.fetch_token(
            OAUTH_TOKEN_URL,
            client_secret=self.client_secret,
            authorization_response=str(request.url),
        )
        request.session["oauth_token"] = resp

        login = OAuth2Session(OAUTH_CLIENT_ID, token=request.session["oauth_token"])
        user = login.get(OAUTH_USER_INFO_URL).json()

        if OAUTH_GOOGLE:
            user = user.get("email", "")
        else:
            user = user["fields"]["username"]

        request.session["user"] = user

        if request.session["type_logout"] == "voter":
            return await self.check_voter(db_session, short_name, user)

        elif request.session["type_logout"] == "trustee" and not isPanel:
            return await self.check_trustee(db_session, short_name, request)
        
        elif isPanel:
            trustee = await crud.get_trustee_by_login_id(session=db_session, trustee_login_id=user)
            if trustee:
                request.session["trustee_uuid"] = trustee.uuid

            return RedirectResponse(url=APP_FRONTEND_URL + f"psifos/trustee/panel")
