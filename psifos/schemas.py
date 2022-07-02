"""
Marshmallow Schemas for Psifos models.
01-04-2022
"""

from marshmallow_enum import EnumField

from psifos import ma
from psifos.crypto.decryption import TrusteeDecryptions
from psifos.crypto.elgamal import PublicKey
from psifos.crypto.sharedpoint import (
    Certificate,
    ListOfCoefficients,
    ListOfSignatures,
    Point
)
from psifos.crypto.tally.common.encrypted_vote import EncryptedVote
from psifos.crypto.tally.tally import TallyManager
from psifos.custom_fields.enums import ElectionStatusEnum, ElectionTypeEnum
from psifos.custom_fields.marshmallow import SerializableField
from psifos.models import (
    AuditedBallot,
    CastVote,
    Election,
    SharedPoint,
    Trustee, 
    Voter
)
from psifos.psifos_object.questions import Questions


class CastVoteSchema(ma.SQLAlchemyAutoSchema):

    # Schema for CastVote detail

    class Meta:
        model = CastVote
        load_instance = True
        include_fk = True

    # Custom fields:
    vote = SerializableField(EncryptedVote)


class AuditedBallotSchema(ma.SQLAlchemyAutoSchema):

    # Schema for AuditedBallot detail

    class Meta:
        model = AuditedBallot
        load_instance = True
        include_fk = True


class TrusteeSchema(ma.SQLAlchemyAutoSchema):

    # Schema for Trustee detail

    class Meta:
        model = Trustee
        load_instance = True
        include_fk = True

    # Custom fields:
    public_key = SerializableField(PublicKey)
    secret_key = ma.auto_field()  # SerializableField(SecretKey)
    pok = ma.auto_field()  # SerializableField(DLogProof)

    certificate = SerializableField(Certificate)
    coefficients = SerializableField(ListOfCoefficients)
    acknowledgements = SerializableField(ListOfSignatures)

    decryptions = SerializableField(TrusteeDecryptions)


class SharedPointSchema(ma.SQLAlchemyAutoSchema):

    # Schema for SharedPoint detail

    class Meta:
        model = SharedPoint
        load_instance = True
        include_fk = True

    # Custom fields
    point = SerializableField(Point)


class VoterSchema(ma.SQLAlchemyAutoSchema):

    # Schema for the Voter detail

    class Meta:
        model = Voter
        load_instance = True
        include_relationships = True
        include_fk = True

    # One-to-one relationship
    cast_vote = ma.Nested(CastVoteSchema)


class ElectionSchema(ma.SQLAlchemyAutoSchema):

    # Schema for the Election detail

    class Meta:
        model = Election
        load_instance = True
        include_relationships = True
        include_fk = True

    # Custom fields
    election_type = EnumField(ElectionTypeEnum, by_value=True)
    election_status = EnumField(ElectionStatusEnum, by_value=True)
    public_key = SerializableField(PublicKey)
    questions = SerializableField(Questions)
    private_key = ma.auto_field()  # SerializableField(SecretKey)
    total_trustees = ma.auto_field()

    cast_url = ma.auto_field()
    encrypted_tally = SerializableField(TallyManager)
    result = ma.auto_field()  # SerializableField(Result)

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
