from sqladmin.authentication import AuthenticationBackend
from fastapi import HTTPException
from app.config import SECRET_KEY, TYPE_AUTH, APP_FRONTEND_URL
from app.psifos_auth.model import crud as auth_crud
from app.database import SessionLocal
from starlette.requests import Request

import jwt

from werkzeug.security import check_password_hash
from fastapi import HTTPException, Request

class AdminAuth(AuthenticationBackend):
    async def login(self, request: Request) -> bool:
        form = await request.form()
        username, password = form["username"], form["password"]

        if not form or not username or not password:
            raise HTTPException(status_code = 401, detail="an error occurred, please try again") 
        async with SessionLocal() as session:   
            user = await auth_crud.get_user_by_name(session=session, name=username)

        if not user:
            raise HTTPException(status_code = 401, detail = "wrong username or passwords")

        if check_password_hash(user.password, password):
            token = jwt.encode({"public_id": user.public_id}, SECRET_KEY)
            request.session.update({"token": token})
            return True
        else:
            raise HTTPException(status_code = 401, detail = "wrong username or passwords")

    async def logout(self, request: Request) -> bool:
        # Usually you'd want to just clear the session
        request.session.clear()
        return True

    async def authenticate(self, request: Request) -> bool:
        token = request.session.get("token")

        if not token:
            return False

        # Check the token in depth
        return True
