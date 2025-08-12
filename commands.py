from app.database import Base, engine 
from app.config import USE_ASYNC_ENGINE
from app.psifos_auth.utils import create_user, add_admin_to_lection
import asyncio
import sys

async def init_models():
    method = sys.argv[1] if len(sys.argv) > 1 else None
    methods = {
        "create_admin": create_admin,
        "add_admin_to_election": add_admin_to_election,
    }
    if method not in methods:
        print(f"Unknown method: {method}. Available methods: {', '.join(methods.keys())}")
        return
    
    if USE_ASYNC_ENGINE:
        async with engine.begin() as conn:
            await methods[method](*sys.argv[2:])
    else:
        await methods[method](*sys.argv[2:])

async def create_admin(username: str, password: str, role: str):
    await create_user(username, password, role)
    print(f"Admin user {username} created successfully")

async def add_admin_to_election(election_short_name: str, username: str):
    await add_admin_to_lection(election_short_name, username)
    print(f"User {username} added as admin to election {election_short_name} successfully")

if __name__ == "__main__":
    asyncio.run(init_models())
