from psifos import db
from psifos.psifos_auth.utils import create_user

db.drop_all()
db.create_all()
create_user("admin", "12345")