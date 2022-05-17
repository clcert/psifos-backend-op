from cas import CASClient
from psifos import config
from flask import request, make_response, redirect, session

from psifos.models import Election, Trustee


class Auth:

    """
    Class in charge of storing all the authentication
    protocols and discriminating which one to use

    """

    def __init__(self) -> None:
        self.cas = CASAuth()
        self.oauth = OAuth2Auth()

    def get_auth(self, **kwargs):
        """
        Returns an instance of Auth.
        """

        return self.cas


class CASAuth:

    """
    Class responsible for solving the logic of
    authentication with the CAS protocol

    """

    def __init__(self) -> None:
        self.cas_client = CASClient(
            version=3,
            service_url=config["URL"]["back"] + "/vote/",
            server_url="https://cas.labs.clcert.cl/",
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
        else:
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

    def login_trustee(self, election_uuid: str, election_schema, trustee_schema):

        cookie = request.cookies.get("session")

        if "username" in session:
            election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
            trustee = Trustee.get_by_login_id_and_election(
                schema=trustee_schema,
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
            election = Election.get_by_uuid(schema=election_schema, uuid=election_uuid)
            trustee = Trustee.get_by_login_id_and_election(
                schema=trustee_schema,
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

    pass
