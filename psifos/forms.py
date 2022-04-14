from wtforms import StringField, SubmitField, PasswordField, IntegerField, Form, ValidationError, DateTimeField, BooleanField, validators
from wtforms.validators import DataRequired, Email, Length
from psifos.models import Election


class ElectionForm(Form):

    short_name = StringField('short_name', validators=[
        DataRequired(), Length(max=100)])

    name = StringField('name', validators=[DataRequired(), Length(max=200)])
    description = StringField('description')

    election_type = StringField('election_type', validators=[
                                DataRequired(), Length(max=50)])

    help_email = StringField('help_email', validators=[
                             validators.Optional(), Email()])
    max_weight = IntegerField('max_weight', validators=[DataRequired()])

    voting_started_at = DateTimeField('voting_started_at')
    voting_ends_at = DateTimeField('voting_ends_at')
    use_voter_aliases = BooleanField('use_voter_aliases')
    randomize_answer_order = BooleanField('randomize_answer_order')
    private_p = BooleanField('private_p')
    normalization = BooleanField('normalization')
