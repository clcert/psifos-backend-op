"""
SQLAlchemy Models for Psifos.

01-04-2022
"""


from __future__ import annotations
from typing import Union
from helios import db, ma
from sqlalchemy.orm import backref
from helios.exceptions import TupleNotFound
from helios.helios_auth.models import User
from helios.serialization import SerializableObject


class PsifosModel():
    """
    Abstraction layer for database I/O, allows the developer to:

    (1) Save instances of db.Model with Python objects as column values by
        serializing them.

    (2) Retrieve tuples from the database with their serialized columns 
        instantiated as their corresponding class.
    
    Usage of the methods:
        Let test_schema = TestSchema(), test_model an instance 
        of TestModel and json_data a version of test_model serilized
        as a JSON like string:

        -> To serialize test_model:
            TestModel.serialize(test_schema, test_model)
            >>> json_data

        -> To deserialize json_data:
            TestModel.deserialize(test_schema, json_data)
            >>> test_model
        
        
        -> To execute a query (Ex: TestModel.query.filter_by(id=1)):
            TestModel.execute(test_schema, TestModel.query.filter_by, id=1)

        -> To save test_model:
            TestModel.save(test_schema, test_model)
    """
    @classmethod
    def serialize(cls, schema: Union[ma.SQLAlchemyAutoSchema, ma.SQLAlchemySchema], obj: PsifosModel) -> str:
        """
        Serializes a PsifosModel object into a JSON like string.
        """
        return schema.dumps(obj)

    @classmethod
    def deserialize(cls, schema: Union[ma.SQLAlchemyAutoSchema, ma.SQLAlchemySchema], json_data: str) -> PsifosModel:
        """
        Deserializes a JSON like string into it's corresponding PsifosModel subclass.
        """
        return schema.loads(json_data)
    
    @classmethod
    def execute(cls, schema: Union[ma.SQLAlchemyAutoSchema, ma.SQLAlchemySchema], fun, *args, **kwargs):
        """
        Executes a md.Model function and after that, deserializes the output.
        """
        def __deserialize_model_instance(x):
            return cls.deserialize(schema, cls.serialize(schema, x))

        return [__deserialize_model_instance(x) for x in fun(*args, **kwargs)]
    
    @classmethod
    def filter_by(cls, schema: Union[ma.SQLAlchemyAutoSchema, ma.SQLAlchemySchema], *args, **kwargs):
        """
        Makes more readable the execution of the filter_by method of SQLAlchemy.
        """
        return cls.execute(schema, cls.query.filter_by, *args, **kwargs)
    
    def save(self) -> None:
        """
        Saves in the database an instance of the model (serializes all columns with a python object as value).
        """
        class_attributes = [attr for attr in dir(self) if not attr.startswith("_")]
        for attr in class_attributes:
            attr_value = getattr(self, attr)
            if isinstance(attr_value, SerializableObject):
                setattr(self, attr, SerializableObject.serialize(attr_value))
        db.session.add(self)
        db.session.commit()

class Election(PsifosModel, db.Model):

    __tablename__ = "helios_election"

    id = db.Column(db.Integer, primary_key=True)

    uuid = db.Column(db.String(50), nullable=False)
    datatype = db.Column(db.String(250), nullable=False,
                         default="legacy/Election")

    short_name = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(250))

    _ELECTION_TYPES = (
        ('election', 'Election'),
        ('referendum', 'Referendum'),
        ('query', 'Query')
    )

    election_type = db.Column(
        db.String(250), nullable=False, default="election")
    private_p = db.Column(db.Boolean, default=False, nullable=False)
    description = db.Column(db.Text)

    public_key = db.Column(db.JSON, nullable=True)
    private_key = db.Column(db.JSON, nullable=True)
    questions = db.Column(db.Text, nullable=True)
    eligibility = db.Column(db.JSON, nullable=True)

    # open registration?
    # this is now used to indicate the state of registration,
    # whether or not the election is frozen
    openreg = db.Column(db.Boolean, default=False)

    # featured election?
    featured_p = db.Column(db.Boolean, default=False)

    # voter aliases?
    use_voter_aliases = db.Column(db.Boolean, default=False)

    # auditing is not for everyone
    use_advanced_audit_features = db.Column(
        db.Boolean, default=True, nullable=False)

    # randomize candidate order?
    randomize_answer_order = db.Column(
        db.Boolean, default=False, nullable=False)

    # where votes should be cast
    cast_url = db.Column(db.String(500))

    # dates at which this was touched
    created_at = db.Column(db.DateTime, default=db.func.now())
    modified_at = db.Column(
        db.DateTime, default=db.func.now(), onupdate=db.func.now())

    # dates at which things happen for the election
    frozen_at = db.Column(db.DateTime, default=None, nullable=True)
    archived_at = db.Column(db.DateTime, default=None, nullable=True)

    # dates for the election steps, as scheduled
    # these are always UTC
    registration_starts_at = db.Column(
        db.DateTime, default=None, nullable=True)
    voting_started_at = db.Column(db.DateTime, default=None, nullable=True)
    voting_ends_at = db.Column(db.DateTime, default=None, nullable=True)

    # if this is non-null, then a complaint period, where people can cast a quarantined ballot.
    # we do NOT call this a "provisional" ballot, since provisional implies that the voter has not
    # been qualified. We may eventually add this, but it can't be in the same CastVote table, which
    # is tied to a voter.
    complaint_period_ends_at = db.Column(
        db.DateTime, default=None, nullable=True)

    tallying_startes_at = db.Column(db.DateTime, default=None, nullable=True)

    # dates when things were forced to be performed
    voting_started_at = db.Column(db.DateTime, default=None, nullable=True)
    voting_extended_until = db.Column(db.DateTime, default=None, nullable=True)
    voting_ends_at = db.Column(db.DateTime, default=None, nullable=True)
    tallying_started_at = db.Column(db.DateTime, default=None, nullable=True)
    tallying_finished_at = db.Column(db.DateTime, default=None, nullable=True)
    tallies_combined_at = db.Column(db.DateTime, default=None, nullable=True)

    # we want to explicitly release results
    result_released_at = db.Column(db.DateTime, default=None, nullable=True)

    # the hash of all voters (stored for large numbers)
    voters_hash = db.Column(db.String(100), nullable=True)

    # encrypted tally, each a JSON string
    # used only for homomorphic tallies
    encrypted_tally = db.Column(db.JSON, nullable=True)

    # results of the election
    result = db.Column(db.JSON, nullable=True)

    # decryption proof, a JSON object
    # no longer needed since it's all trustees
    result_proof = db.Column(db.JSON, nullable=True)

    # help email
    help_email = db.Column(db.String(250), nullable=True)

    # downloadable election info
    election_info_url = db.Column(db.String(300), nullable=True)

    # maximum voter weight
    max_weight = db.Column(db.Integer, nullable=True)

    # normalization on results
    normalization = db.Column(db.Boolean, nullable=True)

    # stop voting explicitly
    voting_stopped = db.Column(db.Boolean, nullable=True)

    def __repr__(self):
        return '<Election %r>' % self.name

    @classmethod
    def get_by_short_name(cls, schema, short_name) -> Election:
        query = cls.filter_by(schema=schema, short_name=short_name)
        if len(query) > 0:
            return query[0]
        raise TupleNotFound("Election", "short_name", short_name)

    @classmethod
    def get_by_uuid(cls, schema, uuid):
        query = cls.filter_by(schema=schema, uuid=uuid)
        if len(query) > 0:
            return query[0]
        raise TupleNotFound("Election", "uuid", uuid)

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

    __tablename__ = "helios_voter"

    id = db.Column(db.Integer, primary_key=True)
    election = db.Column(db.Integer, db.ForeignKey('helios_election.id'))

    uuid = db.Column(db.String(50), nullable=False)

    user = db.relationship("Election", backref=backref(
        'helios_voter', uselist=False))

    voter_login_id = db.Column(db.String(100))
    voter_password = db.Column(db.String(100))
    voter_name = db.Column(db.String(200))
    voter_email = db.Column(db.String(250))
    voter_weight = db.Column(db.Integer)

    alias = db.Column(db.String(100))

    vote = db.Column(db.JSON)
    vote_hash = db.Column(db.String(100))
    cast_at = db.Column(db.DateTime, default=None, nullable=True)

    @classmethod
    def update_or_create(cls, **kwargs):
        voter = cls.filter_by(
            election=kwargs['election'], voter_name=kwargs['voter_name']).first()
        if voter:
            for key, value in kwargs.items():
                setattr(voter, key, value)
        else:
            voter = cls(**kwargs)
        voter.save()
        return voter


class TestModel(PsifosModel, db.Model):
    __tablename__ = "test_model"

    id = db.Column(db.Integer, primary_key=True)
    test_object = db.Column(db.String(255), nullable=False)
