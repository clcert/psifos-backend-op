"""
Marshmallow Schemas for Psifos Auth models.

01-04-2022
"""

from psifos import ma
from psifos.psifos_auth.models import User
from psifos.schemas import ElectionSchema


class UserSchema(ma.SQLAlchemySchema):

    # Schema for the User detail

    class Meta:
        model = User
        load_instance = True
        include_relationships = True
    
    
    id = ma.auto_field()
    public_id = ma.auto_field()
    user_type = ma.auto_field()
    user_id = ma.auto_field()
    name = ma.auto_field()
    password = ma.auto_field()
    admin_p = ma.auto_field()
    elections = ma.Nested(ElectionSchema, many=True)
    


