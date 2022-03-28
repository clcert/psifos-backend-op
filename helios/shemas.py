from helios import ma
from helios.models import Election, Voter


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