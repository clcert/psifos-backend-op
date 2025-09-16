from cas import CASClient
from oic.oic import Client
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.oic.message import AuthorizationResponse, RegistrationResponse, ProviderConfigurationResponse
from oic import rndstr
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
    OIDC_CLIENT_ID,
    OIDC_CLIENT_SECRET,
    OIDC_PROVIDER_URL,
    OIDC_AUTHORIZE_URL,
    OIDC_TOKEN_URL,
)
from app.psifos.model.cruds import crud
from requests_oauthlib import OAuth2Session
from app.database import db_handler
from urllib.parse import urlparse, parse_qs
import requests
import json
import base64

from fastapi import Request, HTTPException
from starlette.responses import RedirectResponse
from app.logger import psifos_logger, logger
from app.psifos.model.enums import ElectionAdminEventEnum, ElectionLoginTypeEnum

from app.psifos_auth.redis_store import store_session_data, get_session_data, delete_session_data, generate_session_id


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
        elif type_auth == "oidc":
            return OIDCAuth()


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

    async def check_voter(self, db_session, short_name: str, user_id: str, request: Request):
        """
        Check if the voter that logs in exists and redirects
        """

        query_params = [
            crud.models.Election.id,
            crud.models.Election.voters_login_type,
        ]

        election = await crud.get_election_params_by_name(
            session=db_session, short_name=short_name, params=query_params
        )
        voter = await crud.get_voter_by_login_id_and_election_id(
            db_session, user_id, election.id
        )

        if (voter is not None) or (
            not election.voters_login_type == ElectionLoginTypeEnum.close_p
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
        self.home_pages = {
            "voter": APP_FRONTEND_URL + "psifos/booth/",
            "trustee": APP_FRONTEND_URL + "psifos/trustee/",
        }

    async def login(self, short_name: str = None, user_type: str = None, request: Request = None, panel: bool = False):
        session_id = generate_session_id()
        request.session["session_id"] = session_id
        client = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=APP_BACKEND_OP_URL + "authorized",
            scope=self.scope,
        )
        authorization_url, state = client.authorization_url(OAUTH_AUTHORIZE_URL)
        await store_session_data(session_id, {"short_name": short_name, "type_logout": user_type, "oauth_state": state, "panel": panel}, expires_in=3600)
        return RedirectResponse(authorization_url)
    
    async def logout(self, user_type: str, request: Request):
        session_id = request.session.get("session_id")
        await delete_session_data(session_id)
        request.session.clear()
        return RedirectResponse(url=self.home_pages[user_type])

    @db_handler.method_with_session
    async def authorized(self, db_session, request: Request):
        try:
            session_id = request.session.get("session_id")
            if not session_id:
                raise HTTPException(status_code=400, detail="Sesión no encontrada.")

            session_data = await get_session_data(session_id)
            if not session_data:
                raise HTTPException(status_code=400, detail="Datos de sesión no válidos.")

            login = OAuth2Session(
                self.client_id,
                state=session_data["oauth_state"],
                redirect_uri=APP_BACKEND_OP_URL + "authorized",
            )
            resp = login.fetch_token(
                OAUTH_TOKEN_URL,
                client_secret=self.client_secret,
                authorization_response=str(request.url),
            )
            session_data["oauth_token"] = resp

            login = OAuth2Session(OAUTH_CLIENT_ID, token=session_data["oauth_token"])
            user = login.get(OAUTH_USER_INFO_URL).json()

            if OAUTH_GOOGLE:
                user = user.get("email", "")
            else:
                user = user["fields"]["username"]
                #user = user["preferred_username"]
            session_data["user"] = user
            await store_session_data(session_id, session_data, expires_in=3600)

            if session_data["type_logout"] == "voter":
                # return await self.check_voter(db_session, short_name, user)
                return await self.check_voter(db_session, session_data["short_name"], user, request)

            elif session_data["type_logout"] == "trustee" and not session_data["panel"]:
                return await self.check_trustee(db_session, session_data["short_name"], request)
            
            elif session_data["panel"]:
                trustee_params = [crud.models.Trustee.id]
                trustee = await crud.get_trustee_params_by_username(session=db_session, username=user, params=trustee_params)
                if trustee:
                    request.session["trustee_id"] = trustee.id

                return RedirectResponse(url=APP_FRONTEND_URL + f"psifos/trustee/panel")
        except Exception as e:
            logger.error(f"Error during OAuth2 authorization: {e}")
            return self.logout(session_data["type_logout"], request)


class OIDCAuth(AbstractAuth):
    def __init__(self) -> None:
        config = {
            "client_id": OIDC_CLIENT_ID,
            "client_secret": OIDC_CLIENT_SECRET,
            "redirect_uri": APP_BACKEND_OP_URL + "authorized",
            "provider_url": OIDC_PROVIDER_URL,
            "scopes": ["openid", "email"] if "google" in OIDC_PROVIDER_URL else ["openid"],
            "dynamic_registration": False,
            "provider_info": {
                "issuer": OIDC_PROVIDER_URL,
                "authorization_endpoint": OIDC_AUTHORIZE_URL,
                "token_endpoint": OIDC_TOKEN_URL
            }
        }
        
        self.config = config
        self.client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
        self.client.clock_skew = 300
        
        self.state = None
        self.nonce = None

        self.short_name = ""
        self.type_logout = ""
        self.home_pages = {
            "voter": APP_FRONTEND_URL + "psifos/booth/",
            "trustee": APP_FRONTEND_URL + "psifos/trustee/",
        }

        op_info = ProviderConfigurationResponse(**self.config['provider_info'])
        self.client.handle_provider_config(op_info, op_info['issuer'])

        client_reg = RegistrationResponse(
                client_id=self.config['client_id'],
                client_secret=self.config.get('client_secret'),
                redirect_uris=[self.config['redirect_uri']]
            )
        self.client.store_registration_info(client_reg)

    def base64url_decode(self, encoded_str, to_string=True):
        # Reemplazar caracteres de Base64URL
        encoded_str = encoded_str.replace('-', '+').replace('_', '/')
        
        # Añadir padding con '=' si es necesario
        padding = len(encoded_str) % 4
        if padding:
            encoded_str += '=' * (4 - padding)
        
        # Decodificar
        decoded_bytes = base64.b64decode(encoded_str)
        
        if to_string:
            return decoded_bytes.decode('utf-8')
        else:
            return decoded_bytes
    
    def split_jwt(self, token):
        """
        Divide un JWT en sus tres componentes: header, payload y signature
        """
        parts = token.split('.')
        
        if len(parts) != 3:
            raise ValueError(f"Token JWT invÃ¡lido. Esperaba 3 partes, obtuvo {len(parts)}")
        
        header, payload, signature = parts
        return header, payload, signature
    
    def decode_jwt_param(self, param_encoded):
        try:
            param_decoded = self.base64url_decode(param_encoded)
            param_json = json.loads(param_decoded)
            return param_json
        except (base64.binascii.Error, json.JSONDecodeError) as e:
            raise ValueError(f"Error decodificando el header: {str(e)}")
    
    async def login(self, short_name: str = None, user_type: str = None, request: Request = None, panel: bool = False):
        self.state = rndstr()
        self.nonce = rndstr() 

        args = {
            "client_id": self.client.client_id,
            "response_type": "code",
            "scope": self.config['scopes'],
            "nonce": self.nonce,
            "redirect_uri": self.config['redirect_uri'],
            "state": self.state,
            "access_type": "offline",
            "prompt": "consent"
        }

        session_id = generate_session_id()
        request.session["session_id"] = session_id
        
        auth_req = self.client.construct_AuthorizationRequest(request_args=args)
        await store_session_data(session_id, {"short_name": short_name, "type_logout": user_type, "oauth_state": self.state, "panel": panel}, expires_in=3600)

        auth_url = auth_req.request(self.client.authorization_endpoint)
        return RedirectResponse(auth_url)

    async def logout(self, user_type: str, request: Request):
        session_id = request.session.get("session_id")
        await delete_session_data(session_id)
        request.session.clear()
        return RedirectResponse(url=self.home_pages[user_type])

    @db_handler.method_with_session
    async def authorized(self, db_session, request: Request):
        redirect_url = str(request.url)
        
        session_id = request.session.get("session_id")
        if not session_id:
            raise HTTPException(status_code=400, detail="Sesión no encontrada")

        session_data = await get_session_data(session_id)
        if not session_data:
            raise HTTPException(status_code=400, detail="Datos de sesión no válidos")
        
        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)
        returned_state = params['state'][0]
        
        if returned_state != session_data["oauth_state"]:
            # State mismatch detected; possible CSRF attack.
            raise ValueError("Error: El state no coincide. Posible ataque CSRF.")
        
        # Parsear la respuesta de autorizaciÃ³n
        auth_response = self.client.parse_response(
            AuthorizationResponse,
            info=redirect_url,
            sformat="urlencoded"
        )

        args = {
            "code": auth_response['code'],
            "client_id": self.client.client_id,
            "client_secret": self.config.get('client_secret'),
            "redirect_uri": self.config['redirect_uri'],
            "grant_type": "authorization_code"
        }
        
        token_response = requests.post(
            self.client.token_endpoint,
            data=args,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        token_info = token_response.json()
        if "error" in token_info:
            raise ValueError(f"Error al obtener tokens: {token_info}")

        id_token = token_info.get('id_token')
        _, payload, _ = self.split_jwt(id_token)

        # header_decoded = self.decode_jwt_param(header)
        payload_decoded = self.decode_jwt_param(payload)
        # signature_decoded = self.base64url_decode(signature, to_string=False).hex()

        issuer =  payload_decoded.get('iss', '')
        if 'google' in issuer:
            user = payload_decoded.get('email', '')
        else:
            user = payload_decoded.get('sub', '')

        session_data["user"] = user
        await store_session_data(session_id, session_data, expires_in=3600)

        if session_data["type_logout"] == "voter":
            return await self.check_voter(db_session, session_data["short_name"], user, request)

        elif session_data["type_logout"] == "trustee" and not session_data["panel"]:
            return await self.check_trustee(db_session, session_data["short_name"], request)
        
        elif session_data["panel"]:
            trustee_params = [crud.models.Trustee.id]
            trustee = await crud.get_trustee_params_by_username(session=db_session, username=user, params=trustee_params)
            if trustee:
                request.session["trustee_id"] = trustee.id

            return RedirectResponse(url=APP_FRONTEND_URL + f"psifos/trustee/panel")
