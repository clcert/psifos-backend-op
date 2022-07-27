"""
Marshmallow Schemas for Psifos Auth models.

01-04-2022
"""

from psifos import ma
from psifos.psifos_auth.models import User
from psifos.database.schemas import ElectionSchema


class UserSchema(ma.SQLAlchemyAutoSchema):

    # Schema for the User detail

    class Meta:
        model = User
        load_instance = True
        include_relationships = True

    elections = ma.Nested(ElectionSchema, many=True)


user_schema = UserSchema()
