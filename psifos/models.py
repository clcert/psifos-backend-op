"""
SQLAlchemy Models for Psifos.

01-04-2022
"""

from __future__ import annotations
from enum import unique
from psifos import db
from psifos.psifos_auth.models import User
from psifos.psifos_model import PsifosModel 
from psifos.enums import ElectionTypeEnum

class Election(PsifosModel, db.Model):
    __tablename__ = "psifos_election"

    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('auth_user.id'))
    uuid = db.Column(db.String(50), nullable=False, unique=True)

    short_name = db.Column(db.String(100), nullable=False, unique=True)
    name = db.Column(db.String(250), nullable=False)
    election_type = db.Column(db.Enum(ElectionTypeEnum), nullable=False)
    private_p = db.Column(db.Boolean, default=False, nullable=False)
    description = db.Column(db.Text)

    public_key = db.Column(db.Text, nullable=True)  # PsifosObject: EGPublicKey
    private_key = db.Column(db.Text, nullable=True) # PsifosObject: EGSecretKey
    questions = db.Column(db.Text, nullable=True)   # PsifosObject: Questions
    openreg = db.Column(db.Boolean, default=False)

    obscure_voter_names = db.Column(db.Boolean, default=False, nullable=False) 
    randomize_answer_order = db.Column(db.Boolean, default=False, nullable=False)
    normalization = db.Column(db.Boolean, default=False, nullable=False)
    max_weight = db.Column(db.Integer, nullable=False)
    
    total_voters = db.Column(db.Integer, nullable=True)
    total_trustes = db.Column(db.Integer, nullable=True)

    cast_url = db.Column(db.String(500))
    encrypted_tally = db.Column(db.Text, nullable=True) # PsifosObject: Tally
    encrypted_tally_hash = db.Column(db.String(500), nullable=True)
    encrypted_open_answers = db.Column(db.Text, nullable=True)
    mixnet_open_answers = db.Column(db.Text, nullable=True)

    result = db.Column(db.Text, nullable=True)  # PsifosObject: Result
    open_answers_result = db.Column(db.Text, nullable=True) # PsifosObject: Result (?)

    voting_started_at = db.Column(db.DateTime, nullable=True)
    voting_ended_at = db.Column(db.DateTime, nullable=True)
    
    # One-to-many relationships
    voters = db.relationship("Voter", backref="psifos_election")
    trustees = db.relationship("Trustee", backref="psifos_election")
    sharedpoints = db.relationship("SharedPoint", backref="psifos_election")
    audited_ballots = db.relationship("AuditedBallot", backref="psifos_election")

    def __repr__(self):
        return '<Election %r>' % self.name

    @classmethod
    def get_by_short_name(cls, schema, short_name) -> Election:
        query = cls.filter_by(schema=schema, short_name=short_name)
        return query[0] if len(query) > 0 else None

    @classmethod
    def get_by_uuid(cls, schema, uuid):
        query = cls.filter_by(schema=schema, uuid=uuid)
        return query[0] if len(query) > 0 else None

    @classmethod
    def update_or_create(cls, schema, **kwargs):
        election = cls.get_by_uuid(schema=schema, uuid=kwargs['uuid'])
        if election is not None:
            for key, value in kwargs.items():
                setattr(election, key, value)
        else:
            election = cls(**kwargs)

        election.save()
        return election


class Voter(PsifosModel, db.Model):
    __tablename__ = "psifos_voter"

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey('psifos_election.id'))
    uuid = db.Column(db.String(50), nullable=False, unique=True)

    voter_login_id = db.Column(db.String(100), nullable=False)
    voter_name = db.Column(db.String(200), nullable=False)
    voter_weight = db.Column(db.Integer, nullable=False)

    # One-to-many relationship
    casted_votes = db.relationship("CastVote", backref="psifos_voter", uselist=False)
    

    @classmethod
    def get_by_name_and_election(cls, schema, voter_name, election):
        query = cls.filter_by(schema=schema, voter_name=voter_name, election=election)
        return query[0] if len(query) > 0 else None

    
    @classmethod
    def update_or_create(cls, schema, **kwargs):
        voter = cls.get_by_name_and_election(
            schema=schema,
            voter_name=kwargs["voter_name"],
            election=kwargs["election"]
        )
        if voter is not None:
            for key, value in kwargs.items():
                setattr(voter, key, value)
        else:
            voter = cls(**kwargs)
        voter.save()
        return voter


class CastVote(PsifosModel, db.Model):
    __table_name__ = "psifos_cast_vote"

    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.Integer, db.ForeignKey("psifos_voter.id"), unique=True)
    
    vote = db.Column(db.Text, nullable=True, unique=True)   # PsifosObject: EncryptedVote
    vote_hash = db.Column(db.String(500), nullable=True, unique=True)
    vote_tinyhash = db.Column(db.String(500), nullable=True, unique=True)
    cast_at = db.Column(db.DateTime, default=db.func.now())
    verified_at = db.Column(db.DateTime, nullable=True)
    invalidated_at = db.Column(db.DateTime, nullable=True)
    hash_cast_ip = db.Column(db.String(500), nullable=True)


class AuditedBallot(PsifosModel, db.Model):
    __table_name__ = "psifos_audited_ballot"

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey("psifos_election.id"))

    raw_vote = db.Column(db.Text)
    vote_hash = db.Column(db.String(500))
    added_at = db.Column(db.DateTime, default=db.func.now())


class Trustee(PsifosModel, db.Model):
    __table_name__ = "psifos_trustee"

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey("psifos_election.id"))
    trustee_id = db.Column(db.Integer, default=0)
    uuid = db.Column(db.String(50), nullable=False, unique=True)
    
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.Text, nullable=False)
    secret = db.Column(db.String(100))

    public_key = db.Column(db.Text, nullable=True)  # PsifosObject: EGPublicKey
    public_key_hash = db.Column(db.String(100), nullable=True)
    secret_key = db.Column(db.Text, nullable=True)  # PsifosObject: EGSecretKey
    pok = db.Column(db.Text, nullable=True)  # PsifosObject: DLogProof
    
    answers_decryption_factors = db.Column(db.Text, nullable=True)  # PsifosObject: Arrayof(Arrayof(BigInteger))
    answers_decryption_proofs = db.Column(db.Text, nullable=True)  # PsifosObject: Arrayof(Arrayof(EGZKProof))
    open_answers_decryption_factors = db.Column(db.Text, nullable=True)  # PsifosObject: Arrayof(Arrayof(BigInteger))
    open_answers_decryption_proofs = db.Column(db.Text, nullable=True)  # PsifosObject: Arrayof(Arrayof(EGZKProof))
    
    certificate = db.Column(db.Text, nullable=True)  # PsifosObject: Certificate
    threshold_step = db.Column(db.Integer, default=0)
    coefficients = db.Column(db.Text, nullable=True)  # PsifosObject: Coefficient
    acknowledgements = db.Column(db.Text, nullable=True)  # PsifosObject: Signature


class SharedPoint(PsifosModel, db.Model):
    __table_name__ = "psifos_shared_point"

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey("psifos_election.id"))
    sender = db.Column(db.Integer, nullable=False)
    recipient = db.Column(db.Integer, nullable=False)
    point = db.Column(db.Text, nullable=True)  # PsifosObject: Point
