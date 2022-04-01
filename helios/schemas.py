from helios import ma
from helios.fields import JSONField
from helios.models import Election, Voter, TestModel
from helios.utils import TestObject
from marshmallow import fields

class ElectionDetailSchema(ma.SQLAlchemyAutoSchema):

    # Schema for the election detail

    class Meta:
        model = Election
        load_instance = True



class VoterSchema(ma.SQLAlchemyAutoSchema):

    # Schema for the voter detail

    class Meta:
        model = Voter
        load_instance = True


class TestSchema(ma.SQLAlchemySchema):
    class Meta:
        model = TestModel
        load_instance = True
    
    id = fields.Integer()
    test_object = JSONField(TestObject)
