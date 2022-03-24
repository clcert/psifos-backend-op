from helios import ma
from helios.models import Election


class ElectionDetailSchema(ma.SQLAlchemyAutoSchema):

    # Schema for the election detail

    class Meta:
        model = Election
        load_instance = True
