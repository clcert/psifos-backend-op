from wtforms import StringField, IntegerField, Form, BooleanField, validators
from wtforms.validators import DataRequired, Length

class ElectionForm(Form):

    short_name = StringField('short_name', validators=[
        DataRequired(), Length(max=100)])

    name = StringField('name', validators=[DataRequired(), Length(max=200)])
    description = StringField('description')

    election_type = StringField('election_type', validators=[
                                DataRequired(), Length(max=50)])

    max_weight = IntegerField('max_weight', validators=[DataRequired()])

    obscure_voter_names = BooleanField('use_voter_aliases')
    randomize_answer_order = BooleanField('randomize_answer_order')
    private_p = BooleanField('private_p')
    normalization = BooleanField('normalization')
