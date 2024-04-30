from datetime import timedelta
from fastapi import FastAPI

from app.config import SECRET_KEY, ORIGINS, TOKEN_ANALYTICS_OP

from .database import Base, engine
from .psifos.routes import api_router
from .psifos_auth.routes import auth_router

from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from starlette_context import middleware, plugins

from api_analytics.fastapi import Analytics

from app.logger import logger

from sqladmin import Admin
from app.admin.auth import AdminAuth
from app.admin.models import ElectionAdmin, VoterAdmin, TrusteeAdmin, CastVoteAdmin

import os

app = FastAPI()

app.logger = logger

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.add_middleware(Analytics, api_key=TOKEN_ANALYTICS_OP)  # Add middleware

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    middleware.ContextMiddleware,
    plugins=(
        plugins.ForwardedForPlugin(),
    ),
)

# Routes
app.include_router(api_router)
app.include_router(auth_router)

# Admin

authentication_backend = AdminAuth(secret_key=SECRET_KEY)
admin = Admin(app, engine, authentication_backend=authentication_backend)
admin.add_view(ElectionAdmin)
admin.add_view(VoterAdmin)
admin.add_view(TrusteeAdmin)
admin.add_view(CastVoteAdmin)

