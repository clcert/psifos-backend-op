from app.psifos.model.models import Election, Voter, Trustee, CastVote
from app.admin.fields import JSONField
from sqladmin import ModelView


class ElectionAdmin(ModelView, model=Election):

    column_list = [Election.short_name, Election.name, Election.election_status]
    form_columns = [
        Election.short_name,
        Election.name,
        Election.election_status,
        Election.public_key,
        Election.questions,
        Election.encrypted_tally,
        Election.election_login_type,
    ]

    form_overrides = dict(
        public_key=JSONField,
        questions=JSONField,
        encrypted_tally=JSONField,
        result=JSONField,
        grouped=JSONField,
    )


class VoterAdmin(ModelView, model=Voter):

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


class TrusteeAdmin(ModelView, model=Trustee):

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

class CastVoteAdmin(ModelView, model=CastVote):

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