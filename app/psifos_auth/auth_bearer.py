from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.config import SECRET_KEY
from sqlalchemy.orm import Session
from app.dependencies import get_db

from app.psifos_auth.model import crud

import jwt

def decodeJWT(token: str, db: Session) -> dict:
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return crud.get_user_by_public_id(public_id=decoded_token["public_id"], db=db) if decoded_token else None
    except:
        raise HTTPException(status_code=401, detail="token is invalid")


class AuthAdmin(HTTPBearer):

    """
    HTTPBearer class for authentication with Bearer tokens.

    """


    def __init__(self, auto_error: bool = True):
        super(AuthAdmin, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request, db: Session = Depends(get_db)):
        credentials: HTTPAuthorizationCredentials = await super(AuthAdmin, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")

            admin_user = self.verify_jwt(credentials.credentials, db)
            if not admin_user:
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")

            return admin_user
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    def verify_jwt(self, jwtoken: str, db: Session) -> bool:
        try:
            return decodeJWT(jwtoken, db)
        except:
            raise HTTPException(status_code=403, detail="Invalid token or expired token.")