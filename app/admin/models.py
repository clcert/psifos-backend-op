from app.psifos.model.models import Election
from app.admin.fields import JSONField
from sqladmin import ModelView

class ElectionAdmin(ModelView, model=Election):
    column_list = [Election.short_name, Election.name, Election.election_status]
    form_columns = [Election.short_name, Election.name, Election.election_status, Election.public_key, Election.questions]
    form_overrides = dict(public_key=JSONField, questions=JSONField)
    
