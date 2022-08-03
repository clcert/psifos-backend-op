"""
Pydantic schemas (FastAPI) for Psifos.

25-07-22


Pydantic schemas are a way to give a 'type' to a group
of related data.

When we deal with SQLAlchemy we must note the following:

    Let 'TestModel' be a SQLAlchemy model, the API can:
        - Create/modify an instance of TestModel.
        - Out an instance of TestModel.
    
    To achieve this we must create 3 schemas:
        - TestModelBase: Inherits from Pydantic's PsifosSchema
          and holds the common data from both creating and
          returning an instance of TestModel.

        - TestModelIn: Inherits from TestModelBase and
          contains the specific data needed to create/modify an
          instance of TestModel.

        - TestModelOut: Inherits from TestModelBase and contains
          the data that we want the API to return to the user.
    
    By doing this we explicitly separate between creation data,
    which could be sensitive, and return data, improving the
    overall security of the API.
"""

from datetime import datetime
from pydantic import BaseModel, Field

from psifos.crypto.elgamal import PublicKey
from psifos.crypto.sharedpoint import Certificate, ListOfCoefficients, ListOfSignatures, Point
from psifos.crypto.tally.common.decryption.trustee_decryption import TrusteeDecryptions
from psifos.crypto.tally.common.encrypted_vote import EncryptedVote
from psifos.crypto.tally.tally import TallyManager
from psifos.psifos_object.questions import Questions
from psifos.psifos_object.result import ElectionResult
from psifos.serialization import SerializableList, SerializableObject
from .enums import ElectionTypeEnum, ElectionStatusEnum


class PsifosSchema(BaseModel):
    """
    Base class for a Psifos schema, includes custom json_encoders.
    """

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            SerializableObject: lambda s_obj: SerializableObject.serialize(s_obj),
            SerializableList: lambda s_list: SerializableList.serialize(s_list),
        }


# ------------------ response-related schemas ------------------
# (TODO)


# ------------------ model-related schemas ------------------


#  Trustee-related schemas


class TrusteeBase(PsifosSchema):
    """
    Basic trustee schema.
    """

    name: str
    email: str
    trustee_login_id: str


class TrusteeIn(TrusteeBase):
    """
    Schema for creating a trustee.
    """

    pass


class TrusteeOut(TrusteeBase):
    """
    Schema for reading/returning trustee data.
    """

    id: int
    trustee_id: int
    uuid: str
    current_step: int
    public_key: PublicKey | None
    public_key_hash: str | None
    decryptions: TrusteeDecryptions | None
    certificate: Certificate | None
    coefficients: ListOfCoefficients | None
    acknowledgements: ListOfSignatures | None

    class Config:
        orm_mode = True


#  CastVote-related schemas


class CastVoteBase(PsifosSchema):
    """
    Basic castvote schema.
    """

    voter_id: int
    vote_hash: str | None
    vote_tinyhash: str | None
    valid_cast_votes: int
    invalid_cast_votes: int
    cast_ip: str | None
    hash_cast_ip: str
    cast_at: datetime | None


class CastVoteIn(CastVoteBase):
    """
    Schema for creating an castvote.
    """

    pass


class CastVoteOut(CastVoteBase):
    """
    Schema for reading/returning castvote data.
    """

    id: int
    vote_hash: str | None
    vote_tinyhash: str | None
    valid_cast_votes: int
    invalid_cast_votes: int
    cast_ip: str | None
    hash_cast_ip: str
    cast_at: datetime | None
    verified_at: datetime | None
    invalidated_at: datetime | None

    class Config:
        orm_mode = True


#  Voter-related schemas


class VoterBase(PsifosSchema):
    """
    Basic election schema.
    """

    voter_login_id: str
    voter_weight: int
    voter_name: str


class VoterIn(VoterBase):
    """
    Schema for creating an election.
    """

    pass


class VoterOut(VoterBase):
    """
    Schema for reading/returning voter data.
    """

    id: int
    uuid: str

    cast_vote: CastVoteOut = None

    class Config:
        orm_mode = True


#  Election-related schemas


class ElectionBase(PsifosSchema):
    """
    Basic election schema.
    """

    short_name: str = Field(max_length=100)
    name: str = Field(max_length=100)
    description: str | None
    election_type: ElectionTypeEnum = Field(max_length=100)
    max_weight: int
    obscure_voter_names: bool | None
    randomize_answer_order: bool | None
    private_p: bool | None
    normalization: bool | None


class ElectionIn(ElectionBase):
    """
    Schema for creating an election.
    """

    pass


class ElectionOut(ElectionBase):
    """
    Schema for reading/returning election data
    """

    id: int
    uuid: str
    election_status: ElectionStatusEnum
    public_key: PublicKey | None
    questions: Questions | None
    total_voters: int
    total_trustees: int
    encrypted_tally: TallyManager | None
    encrypted_tally_hash: str | None
    result: ElectionResult | None
    voters_by_weight_init: str | None
    voters_by_weight_end: str | None

    voters: list[VoterOut] = []
    trustees: list[TrusteeOut] = []

    class Config:
        orm_mode = True
