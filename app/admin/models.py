from app.psifos.model.models import Election, Voter, Trustee, CastVote
from app.admin.fields import JSONField
from starlette_admin.contrib.sqla import ModelView


class ElectionAdmin(ModelView):

    fields = ['id']


class VoterAdmin(ModelView):

    column_list = [
        Voter.voter_login_id,
        Voter.voter_name,
        Voter.election_id,
        Voter.voter_weight,
        Voter.group,
        Voter.valid_cast_votes,
    ]
    form_columns = [
        Voter.voter_login_id,
        Voter.voter_name,
        Voter.election_id,
        Voter.voter_weight,
        Voter.group,
    ]

    form_overrides = dict(
        election_id=JSONField,
    )


class TrusteeAdmin(ModelView):

    column_list = [
        Trustee.id,
        Trustee.trustee_login_id,
        Trustee.name,
        Trustee.election_id,
        Trustee.current_step,
    ]
    form_columns = [
        Trustee.trustee_login_id,
        Trustee.name,
        Trustee.election_id,
        Trustee.public_key,

    ]

    form_overrides = dict(
        election_id=JSONField,
        public_key=JSONField,
    )

class CastVoteAdmin(ModelView):

    column_list = [
        CastVote.id,
        CastVote.voter_id,
        CastVote.vote,
    ]
    form_columns = [
        CastVote.id,
        CastVote.voter_id,
        CastVote.vote,
        CastVote.is_valid,
    ]

    form_overrides = dict(
        election_id=JSONField,
        vote=JSONField,
    )