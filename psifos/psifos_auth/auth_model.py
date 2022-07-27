from urllib import response
from cas import CASClient
from psifos import config, app
from flask import request, make_response, redirect, session, url_for, jsonify
from psifos.database.models import Election, Trustee
from psifos.psifos_auth.utils import get_user
from requests_oauthlib import OAuth2Session


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
            service_url=config["URL"]["back"] + "/vote/",
            server_url=config["CAS"]["cas_url"],
        )

    def redirect_cas(self, redirect_url):
        """
        Redirects to the CAS server

        """

        self.cas_client.service_url = redirect_url
        cas_login_url = self.cas_client.get_login_url()
        return redirect(cas_login_url)

    def login_voter(self, election_uuid: str):
        """
        Login a voter
        """
        cookie = request.cookies.get("session")
        if "username" in session:

            response = redirect(
                config["URL"]["front"] + "/cabina/" + election_uuid, code=302
            )
            response.set_cookie("session", cookie)
            return response

        ticket = request.args.get("ticket")
        if not ticket:
            return self.redirect_cas(config["URL"]["back"] + "/vote/" + election_uuid)

        user, attributes, pgtiou = self.cas_client.verify_ticket(ticket)
        if not user:
            return make_response({"message": "ERROR"}, 401)

        session["username"] = user
        response = redirect(
            config["URL"]["front"] + "/cabina/" + election_uuid, code=302
        )
        return response

    def logout_voter(self, election_uuid: str):

        cas_logout_url = self.cas_client.get_logout_url(
            config["URL"]["front"] + "/cabina/" + election_uuid + "?logout=true"
        )

        response = redirect(cas_logout_url, code=302)
        response.set_cookie("session", expires=0)
        return response

    def login_trustee(self, election_uuid: str):

        cookie = request.cookies.get("session")

        if "username" in session:
            election = Election.get_by_uuid(uuid=election_uuid)
            trustee = Trustee.get_by_login_id_and_election(
                trustee_login_id=session["username"],
                election_id=election.id,
            )
            if not trustee:
                response = redirect(
                    config["URL"]["front"] + "/" + election_uuid + "/trustee" + "/home",
                    code=302,
                )
            else:

                response = redirect(
                    config["URL"]["front"]
                    + "/"
                    + election_uuid
                    + "/trustee/"
                    + trustee.uuid
                    + "/home",
                    code=302,
                )
            response.set_cookie("session", cookie)
            return response

        ticket = request.args.get("ticket")
        if not ticket:
            return self.redirect_cas(
                config["URL"]["back"] + "/" + election_uuid + "/trustee" + "/login",
            )

        user, attributes, pgtiou = self.cas_client.verify_ticket(ticket)
        if not user:
            return make_response({"message": "ERROR"}, 401)
        else:
            session["username"] = user
            election = Election.get_by_uuid(uuid=election_uuid)
            trustee = Trustee.get_by_login_id_and_election(
                trustee_login_id=session["username"],
                election_id=election.id,
            )
            if not trustee:
                response = redirect(
                    config["URL"]["front"] + "/" + election_uuid + "/trustee" + "/home",
                    code=302,
                )
            else:

                response = redirect(
                    config["URL"]["front"]
                    + "/"
                    + election_uuid
                    + "/trustee/"
                    + trustee.uuid
                    + "/home",
                    code=302,
                )
            return response

    def logout_trustee(self, election_uuid: str):

        cas_logout_url = self.cas_client.get_logout_url(
            config["URL"]["front"]
            + "/"
            + election_uuid
            + "/trustee"
            + "/home"
            + "?logout=true"
        )

        response = redirect(cas_logout_url, code=302)
        response.set_cookie("session", expires=0)
        return response


class OAuth2Auth:
    def __init__(self) -> None:
        """
        Class responsible for solving the logic of
        authentication with the OAUTH2 protocol

        """

        self.client_id = config["OAUTH"]["client_id"]
        self.client_secret = config["OAUTH"]["client_secret"]
        self.scope = "openid"
        self.election_uuid = ""
        self.trustee_uuid = ""
        self.type_logout = ""

    def login_voter(self, election_uuid: str):

        self.election_uuid = election_uuid
        self.type_logout = "voter"
        client = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=config["URL"]["back"] + "/authorized",
            scope=self.scope,
        )

        authorization_url, state = client.authorization_url(
            config["OAUTH"]["authorize_url"]
        )
        session["oauth_state"] = state
        return redirect(authorization_url)

    def logout_voter(self, election_uuid: str):

        client = OAuth2Session(
            self.client_id,
            token=session["oauth_token"],
        )

        return redirect(
            "https://cas.labs.clcert.cl/oauth/revoke_token?token=NW0ynxy0paUfPZ1YfvWU6wr7SFJZlm&client_id=Vro0Bd2MoRKEg4Lxn9mc8bySKlMAlbgObf2UeXuY&client_secret=pWegIkGmtVIdfqIsBo3lwuKiAygusL1NbpzT7nzyN6ArfVfEhwglpkD753VzfslAlXQ3vEMYJysUKjxsdsmPlELBnkfA560MhX9lwMyKW3ZKgUNebRQHF5NIu91U2qK6"
        )

    def login_trustee(self, election_uuid: str):

        self.election_uuid = election_uuid
        self.type_logout = "trustee"
        client = OAuth2Session(
            client_id=self.client_id,
            redirect_uri=config["URL"]["back"] + "/authorized",
            scope=self.scope,
        )

        authorization_url, state = client.authorization_url(
            config["OAUTH"]["authorize_url"]
        )
        session["oauth_state"] = state

        return redirect(authorization_url)

    def logout_trustee(self):
        pass

    def authorized(self):

        login = OAuth2Session(
            self.client_id,
            state=session["oauth_state"],
            redirect_uri=config["URL"]["back"] + "/authorized",
        )
        resp = login.fetch_token(
            config["OAUTH"]["token_url"],
            client_secret=self.client_secret,
            authorization_response=request.url,
        )
        session["oauth_token"] = resp

        if self.type_logout == "voter":
            response = redirect(
                config["URL"]["front"] + "/cabina/" + self.election_uuid, code=302
            )

        elif self.type_logout == "trustee":

            election = Election.get_by_uuid(
                uuid=self.election_uuid
            )
            trustee = Trustee.get_by_login_id_and_election(
                trustee_login_id=get_user(),
                election_id=election.id,
            )

            self.trustee_uuid = trustee.uuid if trustee else None

            if not self.trustee_uuid:
                response = redirect(
                    config["URL"]["front"]
                    + "/"
                    + self.election_uuid
                    + "/trustee"
                    + "/home",
                    code=302,
                )
            else:
                response = redirect(
                    config["URL"]["front"]
                    + "/"
                    + self.election_uuid
                    + "/trustee/"
                    + self.trustee_uuid
                    + "/home",
                    code=302,
                )

        return response
