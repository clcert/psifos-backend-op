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

from app.database.serialization import SerializableList, SerializableObject
from app.psifos.model.enums import ElectionTypeEnum, ElectionStatusEnum, ElectionLoginTypeEnum

from typing import Optional

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


# ------------------ model-related schemas ------------------

class PublicKeyBase(PsifosSchema):
    """
    Basic public key schema.
    """

    y: str
    p: str
    g: str
    q: str

    class Config:
        orm_mode = True

class QuestionBase(PsifosSchema):
    """
    Schema for creating a question.
    """
    q_num: int
    q_type: str
    q_text: str
    q_description: str | None
    total_options: int
    total_closed_options: int
    closed_options: str | None
    max_answers: int
    min_answers: int
    include_blank_null: bool | None
    tally_type: str
    group_votes: bool | None
    num_of_winners: int | None

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


# model (sqla) ModelElection -> SchemaElection
class TrusteeOut(TrusteeBase):
    """
    Schema for reading/returning trustee data.
    """

    id: int
    trustee_id: int
    uuid: str
    current_step: int
    public_key: PublicKeyBase | None
    public_key_hash: str | None
    decryptions: object | None
    certificate: object | None
    coefficients: object | None
    acknowledgements: object | None

    class Config:
        orm_mode = True


#  CastVote-related schemas


class CastVoteBase(PsifosSchema):
    """
    Basic castvote schema.
    """

    encrypted_vote: str | None


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
    vote_hash: str
    # vote_tinyhash: str | None

    cast_ip: str
    cast_ip_hash: str
    is_valid: bool

    cast_at: datetime

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
    group: str | None


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

    valid_cast_votes: int
    invalid_cast_votes: int

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
    election_login_type: ElectionLoginTypeEnum =Field(max_length=100)
    normalization: bool | None
    grouped: bool | None


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
    decryptions_uploaded: int
    public_key: PublicKeyBase | None
    questions: object | None
    total_voters: int
    total_trustees: int
    encrypted_tally_hash: str | None
    result: object | None
    voters_by_weight_init: str | None
    voters_by_weight_end: str | None
    trustees: object | None


    class Config:
        orm_mode = True

class SimpleElection(ElectionBase):

    id: int
    uuid: str
    election_status: ElectionStatusEnum
    decryptions_uploaded: int
    total_voters: int
    total_trustees: int


    class Config:
        orm_mode = True

class CompleteElectionOut(ElectionOut):
    encrypted_tally: object | None

    class Config:
        orm_mode = True


# ------------------ response-related schemas ------------------


class PublicKeyData(PsifosSchema):
    public_key_json: str


class KeyGenStep1Data(PsifosSchema):
    coefficients: str
    points: str


class KeyGenStep2Data(PsifosSchema):
    acknowledgements: str


class KeyGenStep3Data(PsifosSchema):
    verification_key: str


class DecryptionIn(PsifosSchema):
    group: str
    with_votes: bool
    decryptions: object


class TrusteeHome(PsifosSchema):
    trustee: TrusteeOut
    election: ElectionOut
