from fastapi import Request, HTTPException, Depends, Cookie
from fastapi.security import HTTPBearer
from app.config import SECRET_KEY
from sqlalchemy.orm import Session
from app.dependencies import get_session
from sqlalchemy.ext.asyncio import AsyncSession

from app.psifos_auth.model import crud

import jwt

async def decodeJWT(token: str, session: Session | AsyncSession) -> dict:
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return await crud.get_user_by_public_id(public_id=decoded_token["public_id"], session=session) if decoded_token else None
    except:
        raise HTTPException(status_code=401, detail="token is invalid")


class AuthAdmin(HTTPBearer):

    """
    HTTPBearer class for authentication with Bearer tokens.

    """

    def __init__(self, auto_error: bool = True):
        super(AuthAdmin, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request, session: Session | AsyncSession = Depends(get_session), access_token: str = Cookie(None)):
        if access_token:
            admin_user = await self.verify_jwt(access_token, session)
            if not admin_user:
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return admin_user
        else:
            raise HTTPException(status_code=403, detail="Authorization token not provided.")

    async def verify_jwt(self, jwtoken: str, session: Session | AsyncSession) -> bool:
        try:
            return await decodeJWT(jwtoken, session)
        except:
            raise HTTPException(status_code=403, detail="Invalid token or expired token.")
