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
from pydantic import BaseModel, Field, validator, root_validator

from app.database.serialization import SerializableList, SerializableObject
from app.psifos.model.enums import ElectionTypeEnum, ElectionStatusEnum, ElectionLoginTypeEnum, TrusteeStepEnum

from typing import Optional, List

import json

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

class DecryptionIn(PsifosSchema):
    group: str
    with_votes: bool
    decryptions: object

#  Trustee-related schemas

class TrusteeCryptoBase(PsifosSchema):
    """
    Basic trustee schema.
    """
    trustee_election_id: int | None
    current_step: TrusteeStepEnum | None
    public_key: str | object | None
    public_key_hash: str | None
    decryptions: str | object | None
    certificate: str | object | None
    coefficients: str | object | None
    acknowledgements: str | object | None
    election_id: int | None

    class Config:
        orm_mode = True


class TrusteeCryptoPanel(TrusteeCryptoBase):
    """
    Basic trustee schema.
    """
    election_short_name: str | None
    election_status: str | None

    class Config:
        orm_mode = True


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

class DecryptionBase(PsifosSchema):
    """
    Basic decryption schema.
    """

    trustee_id: int | None
    decryption_type: str | None
    decryption_factors: object | None
    decryption_proofs: object | None

    class Config:
        orm_mode = True

class TallyBase(PsifosSchema):
    """
    Basic tally schema.
    """
    group: str | None
    with_votes: bool
    tally_type: str
    index: int
    num_options: int
    computed: bool
    num_tallied: int
    max_answers: int | None
    num_of_winners: int | None
    include_informal_options: bool | None
    encrypted_tally: object | None

    class Config:
        orm_mode = True

class QuestionBase(PsifosSchema):
    """
    Schema for creating a question.
    """
    index: int
    type: str
    title: str
    description: str | None
    formal_options: List[str] | None
    total_options: int
    max_answers: int
    min_answers: int
    include_informal_options: bool | None
    excluded_options: bool | None
    tally_type: str
    grouped_options: bool | None
    num_of_winners: int | None
    options_specifications: List[str] | None

    class Config:
        orm_mode = True

#  Trustee-related schemas

class TrusteeBase(PsifosSchema):
    """
    Basic trustee schema.
    """

    name: str
    email: str
    username: str

    class Config:
        orm_mode = True


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

    is_valid: bool

    cast_at: datetime

    class Config:
        orm_mode = True


#  Voter-related schemas


class VoterBase(PsifosSchema):
    """
    Basic election schema.
    """

    username: str
    weight_init: int
    weight_end: int | None
    name: str
    username_election_id: str
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

    cast_vote: CastVoteOut = None

    class Config:
        orm_mode = True


#  Election-related schemas


class ElectionBase(PsifosSchema):
    """
    Basic election schema.
    """

    short_name: str = Field(max_length=100)
    long_name: str = Field(max_length=100)
    description: str | None
    type: ElectionTypeEnum = Field(max_length=100)
    max_weight: int
    quorum: float | None = None
    randomized_options: bool | None
    voters_login_type: ElectionLoginTypeEnum =Field(max_length=100)
    normalized: bool | None
    grouped_voters: bool | None


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
    status: ElectionStatusEnum
    public_key: PublicKeyBase | None
    encrypted_tally_hash: str | None
    voters_by_weight_init: str | None
    voters_by_weight_end: str | None

    class Config:
        orm_mode = True

class BoothElectionOut(PsifosSchema):

    election: ElectionOut
    questions: List[QuestionBase]
    has_valid_vote: bool = False
    class Config:
        orm_mode = True

class SimpleElection(ElectionBase):

    id: int
    status: ElectionStatusEnum


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


class TrusteePanel(PsifosSchema):
    trustee: TrusteeBase
    trustee_crypto: list[TrusteeCryptoPanel] = []
class DecryptionIn(PsifosSchema):
    group: str
    with_votes: bool
    decryptions: object


class TrusteeHome(PsifosSchema):
    trustee: TrusteeOut
    election: ElectionOut
    decryptions: object
