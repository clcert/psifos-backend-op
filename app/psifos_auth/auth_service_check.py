from fastapi import Request, HTTPException
from app.config import TYPE_AUTH

from app.psifos_auth.redis_store import get_session_data


class AuthUser:
    """
    Class in charge of storing all the authentication
    protocols and discriminating which one to use
    """

    def __init__(self) -> None:
        self.cas = AuthCasCheck()
        self.oauth = AuthOauthCheck()
        self.type_auth = TYPE_AUTH

    async def __call__(self, request: Request) -> object:
        """
        Returns an instance of Auth.
        """

        public_election = request.session.get("public_election", None)
        if public_election:
            return request.session.get("user", None)
        if self.type_auth == "cas":
            return await self.cas.get_login_id(request)
        elif self.type_auth == "oauth":
            return await self.oauth.get_login_id(request)




class AuthServiceCheck(object):

    """
    Abstract class to check the user in the system
    with Auth Service (CAS / OAuth2)     
    
    """


    def get_user_without_domain(self, user_name: str):
        """
        Get the user without the domain
        """
        if user_name[-10:] == "@uchile.cl":
            return user_name[:-10]

        return user_name



class AuthCasCheck(AuthServiceCheck):

    """
    Check if the user is authenticated with CAS
    
    """


    async def get_login_id(self, request: Request):
        session_id = request.session.get("session_id", None)
        if not session_id:
            raise HTTPException(status_code=401, detail="unauthorized")
        session_data = await get_session_data(session_id)
        user = session_data.get("user", None)
        if not user:
            raise HTTPException(status_code=401, detail="unauthorized voter")

        return self.get_user_without_domain(user)


class AuthOauthCheck(AuthServiceCheck):

    """
    Check if the user is authenticated with OAuth2
    
    """


    async def get_login_id(self, request: Request):

        try:
            session_id = request.session.get("session_id", None)
            if not session_id:
                raise HTTPException(status_code=401, detail="unauthorized")
            session_data = await get_session_data(session_id)
            user = session_data.get("user", None)
            if not user or 'oauth_state' not in session_data:
                raise HTTPException(status_code=401, detail="unauthorized voter")

            return self.get_user_without_domain(user)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"error in authentication: {e}")
