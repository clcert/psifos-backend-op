import os

from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette_context import middleware, plugins

from app.config import SECRET_KEY, ORIGINS

def register_middlewares(app):
    # CORS
    app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
    # app.add_middleware(Analytics, api_key=TOKEN_ANALYTICS_OP)  # Add middleware

    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

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
