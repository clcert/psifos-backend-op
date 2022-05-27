"""
Marshmallow Schemas for Psifos models.

01-04-2022
"""

from psifos import ma
from psifos.fields import SerializableField
from psifos.enums import ElectionTypeEnum
from psifos.models import AuditedBallot, CastVote, Election, SharedPoint, Trustee, Voter
from psifos.crypto.sharedpoint import Certificate, Coefficient, ListOfCoefficients, Point, Signature
from psifos.crypto.elgamal import DLogProof, DecryptionFactors, DecryptionProofs, PublicKey, SecretKey
from psifos.psifos_object.questions import Questions
from marshmallow_enum import EnumField


class CastVoteSchema(ma.SQLAlchemySchema):

    # Schema for CastVote detail

    class Meta:
        model = CastVote
        load_instance = True
        include_fk = True

    # Fields:
    id = ma.auto_field()
    voter_id = ma.auto_field()
    total_cast_votes = ma.auto_field()
    invalid_cast_votes = ma.auto_field()
    vote = ma.auto_field()  # SerializableField(EncryptedVote)
    vote_hash = ma.auto_field()
    vote_tinyhash = ma.auto_field()
    cast_at = ma.auto_field()
    verified_at = ma.auto_field()
    invalidated_at = ma.auto_field()
    hash_cast_ip = ma.auto_field()


class AuditedBallotSchema(ma.SQLAlchemyAutoSchema):

    # Schema for AuditedBallot detail

    class Meta:
        model = AuditedBallot
        load_instance = True
        include_fk = True


class TrusteeSchema(ma.SQLAlchemySchema):

    # Schema for Trustee detail

    class Meta:
        model = Trustee
        load_instance = True
        include_fk = True

    # Fields:
    id = ma.auto_field()
    election_id = ma.auto_field()
    trustee_id = ma.auto_field()
    uuid = ma.auto_field()
    name = ma.auto_field()
    trustee_login_id = ma.auto_field()
    email = ma.auto_field()
    secret = ma.auto_field()
    current_step = ma.auto_field()
    public_key = SerializableField(PublicKey)
    public_key_hash = ma.auto_field()
    secret_key = ma.auto_field()  # SerializableField(SecretKey)
    pok = ma.auto_field()  # SerializableField(DLogProof)
    answers_decryption_factors = SerializableField(DecryptionFactors)
    answers_decryption_proofs = SerializableField(DecryptionProofs)
    open_answers_decryption_factors = SerializableField(DecryptionFactors)
    open_answers_decryption_proofs = SerializableField(DecryptionProofs)
    certificate = SerializableField(Certificate)
    coefficients = SerializableField(ListOfCoefficients)
    acknowledgements = SerializableField(Signature)


class SharedPointSchema(ma.SQLAlchemySchema):

    # Schema for SharedPoint detail

    class Meta:
        model = SharedPoint
        load_instance = True
        include_fk = True

    # Fields:
    id = ma.auto_field()
    election_id = ma.auto_field()
    sender = ma.auto_field()
    recipient = ma.auto_field()
    point = SerializableField(Point)


class VoterSchema(ma.SQLAlchemySchema):

    # Schema for the Voter detail

    class Meta:
        model = Voter
        load_instance = True
        include_relationships = True
        include_fk = True

    # Fields:
    id = ma.auto_field()
    election_id = ma.auto_field()
    uuid = ma.auto_field()
    voter_login_id = ma.auto_field()
    voter_name = ma.auto_field()
    voter_weight = ma.auto_field()

    # One-to-one relationship
    casted_votes = ma.Nested(CastVoteSchema)


class ElectionSchema(ma.SQLAlchemySchema):

    # Schema for the Election detail

    class Meta:
        model = Election
        load_instance = True
        include_relationships = True
        include_fk = True

    id = ma.auto_field()
    admin_id = ma.auto_field()
    uuid = ma.auto_field()
    short_name = ma.auto_field()
    name = ma.auto_field()
    election_type = EnumField(ElectionTypeEnum, by_value=True)
    private_p = ma.auto_field()
    description = ma.auto_field()
    public_key = ma.auto_field()  # SerializableField(PublicKey)
    private_key = ma.auto_field()  # SerializableField(SecretKey)
    questions = SerializableField(Questions)
    openreg = ma.auto_field()
    obscure_voter_names = ma.auto_field()
    randomize_answer_order = ma.auto_field()
    normalization = ma.auto_field()
    max_weight = ma.auto_field()
    total_voters = ma.auto_field()
    total_trustees = ma.auto_field()
    cast_url = ma.auto_field()
    encrypted_tally = ma.auto_field()  # SerializableField(Tally)
    encrypted_tally_hash = ma.auto_field()
    encrypted_open_answers = ma.auto_field()
    mixnet_open_answers = ma.auto_field()
    result = ma.auto_field()  # SerializableField(Result)
    open_answers_result = ma.auto_field()  # SerializableField(Result)

    # One-to-many relationships
    voters = ma.Nested(VoterSchema, many=True)
    trustees = ma.Nested(TrusteeSchema, many=True)
    sharedpoints = ma.Nested(SharedPointSchema, many=True)
    audited_ballots = ma.Nested(AuditedBallotSchema, many=True)


election_schema = ElectionSchema()
voter_schema = VoterSchema()
cast_vote_schema = CastVoteSchema()
trustee_schema = TrusteeSchema()
shared_point_schema = SharedPointSchema()
audited_ballot_schema = AuditedBallotSchema()
