"""
Marshmallow Schemas for Psifos models.

01-04-2022
"""

from psifos import ma
from psifos.fields import JSONField
from psifos.models import Election, Voter
from marshmallow import fields

class ElectionSchema(ma.SQLAlchemyAutoSchema):

    # Schema for the election detail

    class Meta:
        model = Election
        load_instance = True



class VoterSchema(ma.SQLAlchemyAutoSchema):

    # Schema for the voter detail

    class Meta:
        model = Voter
        load_instance = True


"""class TestSchema(ma.SQLAlchemySchema):
    class Meta:
        model = TestModel
        load_instance = True
    
    id = fields.Integer()
    test_object = JSONField(TestObject)
"""