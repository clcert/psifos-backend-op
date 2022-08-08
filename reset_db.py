from app.database import Base, engine 
from app.psifos_auth.utils import create_user


Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)

create_user("admin", "12345")