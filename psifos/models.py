"""
SQLAlchemy Models for Psifos.

01-04-2022
"""

from __future__ import annotations
import datetime
import functools
import json

from psifos import db
from psifos.crypto.tally.tally import TallyManager
from psifos.psifos_auth.models import User
from psifos.psifos_model import PsifosModel
from psifos.enums import ElectionTypeEnum
from psifos.crypto.elgamal import ElGamal, fiatshamir_challenge_generator

import psifos.utils as utils


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
    private_key = db.Column(db.Text, nullable=True)  # PsifosObject: EGSecretKey
    questions = db.Column(db.Text, nullable=True)   # PsifosObject: Questions
    openreg = db.Column(db.Boolean, default=False)

    obscure_voter_names = db.Column(db.Boolean, default=False, nullable=False)
    randomize_answer_order = db.Column(db.Boolean, default=False, nullable=False)
    normalization = db.Column(db.Boolean, default=False, nullable=False)
    max_weight = db.Column(db.Integer, nullable=False)

    total_voters = db.Column(db.Integer, default=0)
    total_trustees = db.Column(db.Integer, default=0)

    cast_url = db.Column(db.String(500))
    encrypted_tally = db.Column(db.Text, nullable=True)  # PsifosObject: Tally
    encrypted_tally_hash = db.Column(db.String(500), nullable=True)
    encrypted_open_answers = db.Column(db.Text, nullable=True)
    mixnet_open_answers = db.Column(db.Text, nullable=True)

    result = db.Column(db.Text, nullable=True)  # PsifosObject: Result
    open_answers_result = db.Column(db.Text, nullable=True)  # PsifosObject: Result (?)

    voting_started_at = db.Column(db.DateTime, nullable=True)
    voting_ended_at = db.Column(db.DateTime, nullable=True)
    
    voters_by_weight_init = db.Column(db.Text, nullable=True)
    voters_by_weight_end = db.Column(db.Text, nullable=True)


    # One-to-many relationships
    voters = db.relationship("Voter", backref="psifos_election")
    trustees = db.relationship("Trustee", backref="psifos_election")
    sharedpoints = db.relationship("SharedPoint", backref="psifos_election")
    audited_ballots = db.relationship("AuditedBallot", backref="psifos_election")

    def __repr__(self):
        return '<Election %r>' % self.name

    @classmethod
    def get_by_short_name(cls, schema, short_name, deserialize=False) -> Election:
        query = cls.filter_by(schema=schema, short_name=short_name, deserialize=deserialize)
        return query[0] if len(query) > 0 else None

    @classmethod
    def get_by_uuid(cls, schema, uuid, deserialize=False):
        query = cls.filter_by(schema=schema, uuid=uuid, deserialize=deserialize)
        return query[0] if len(query) > 0 else None

    @classmethod
    def update_or_create(cls, schema, **kwargs):
        election = cls.get_by_uuid(
            schema=schema,
            uuid=kwargs['uuid'],
            deserialize=True
        )
        if election is not None:
            for key, value in kwargs.items():
                setattr(election, key, value)
        else:
            election = cls(**kwargs)
        return election

    def get_eg_params(self, serialize=True):
        """
        Returns the current election params for elgamal encryption.

        If serialize==False, returns an instance of psfios.crypto.elgamal.ElGamal 
        else, returns the instance serialized as a JSON
        """
        params = ElGamal(
            p=16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071,
            q=61329566248342901292543872769978950870633559608669337131139375508370458778917,
            g=14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533,
            l=self.total_trustees,
            t=self.total_trustees//2,
        )
        return ElGamal.serialize(params) if serialize else params

    def start(self, trustees, voters):
        self.voting_started_at = datetime.datetime.utcnow()

        t_first_coefficients = [t.coefficients.instances[0].coefficient for t in trustees]
        
        # MUST discard changes done to trustee instances due to deserializarion before calling 
        # .save() method for any PsifosModel instance, in this case Election.
        Trustee.discard_changes(target=trustees, many=True)

        combined_pk = functools.reduce((lambda x, y: x*y), t_first_coefficients)
        self.public_key = trustees[0].public_key.clone_with_new_y(combined_pk)

        normalized_weights = [v.voter_weight / self.max_weight for v in voters]
        self.voters_by_weight_init = json.dumps({str(w):normalized_weights.count(w) for w in normalized_weights})
        self.save()
    
    def end(self, voters):
        self.voting_ended_at = datetime.datetime.utcnow()

        normalized_weights = [v.voter_weight / self.max_weight for v in voters]
        self.votes_by_weight_final = json.dumps({str(w):normalized_weights.count(w) for w in normalized_weights})
        self.save()


    def compute_tally(self):
        # First we instantiate the TallyManager class.
        tally_params = [{
            "tally_type": q_dict["tally_type"],
            "question": q_dict,
            "public_key": self.public_key
        } for q_dict in json.loads(self.questions)]
        enc_tally = TallyManager(*tally_params)

        # Then we compute the encrypted_tally.
        # enc_tally.compute()


    
    def voting_has_started(self):
        return True if self.voting_started_at is not None else False
    
    def voting_has_ended(self):
        return True if self.voting_ended_at is not None else False

class Voter(PsifosModel, db.Model):
    __tablename__ = "psifos_voter"

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey('psifos_election.id'))
    uuid = db.Column(db.String(50), nullable=False, unique=True)

    voter_login_id = db.Column(db.String(100), nullable=False)
    voter_name = db.Column(db.String(200), nullable=False)
    voter_weight = db.Column(db.Integer, nullable=False)

    # One-to-one relationship
    cast_vote = db.relationship("CastVote", cascade="delete", backref="psifos_voter", uselist=False)

    @classmethod
    def get_by_login_id_and_election(cls, schema, voter_login_id, election_id, deserialize=False):
        query = cls.filter_by(
            schema=schema,
            voter_login_id=voter_login_id,
            election_id=election_id,
            deserialize=deserialize,
        )
        return query[0] if len(query) > 0 else None

    @classmethod
    def update_or_create(cls, schema, **kwargs):
        voter = cls.get_by_login_id_and_election(
            schema=schema,
            voter_login_id=kwargs["voter_login_id"],
            election_id=kwargs["election_id"],
            deserialize=True,
        )
        if voter is not None:
            for key, value in kwargs.items():
                setattr(voter, key, value)
        else:
            voter = cls(**kwargs)
        return voter
    
    @classmethod
    def get_by_election(cls, schema, election_id, deserialize=False):
        return cls.filter_by(
            schema=schema,
            election_id=election_id,
            deserialize=deserialize,
        )
    

class CastVote(PsifosModel, db.Model):
    __table_name__ = "psifos_cast_vote"

    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.Integer, db.ForeignKey("psifos_voter.id"), unique=True)
    
    vote = db.Column(db.Text, nullable=True)   # PsifosObject: EncryptedVote
    vote_hash = db.Column(db.String(500), nullable=True)
    vote_tinyhash = db.Column(db.String(500), nullable=True)

    valid_cast_votes = db.Column(db.Integer, default=0)
    invalid_cast_votes = db.Column(db.Integer, default=0)
    
    cast_ip = db.Column(db.Text, nullable=True)
    hash_cast_ip = db.Column(db.String(500), nullable=True)
    
    cast_at = db.Column(db.DateTime, default=db.func.now(), nullable=True)
    verified_at = db.Column(db.DateTime, nullable=True)
    invalidated_at = db.Column(db.DateTime, nullable=True)

    @classmethod
    def get_by_voter_id(cls, schema, voter_id, deserialize=False):
        query = cls.filter_by(schema=schema, voter_id=voter_id, deserialize=deserialize)
        return query[0] if len(query) > 0 else None

    @classmethod
    def update_or_create(cls, schema, **kwargs):
        cast_vote = cls.get_by_voter_id(
            schema=schema,
            voter_id=kwargs["voter_id"],
            deserialize=True,
        )
        if cast_vote is not None:
            for key, value in kwargs.items():
                setattr(cast_vote, key, value)
        else:
            cast_vote = cls(**kwargs)
        return cast_vote
    
    def verify(self, election):
        return self.vote.verify(election)



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
    trustee_id = db.Column(db.Integer, nullable=False)
    uuid = db.Column(db.String(50), nullable=False, unique=True)

    name = db.Column(db.String(200), nullable=False)
    trustee_login_id = db.Column(db.String(100), nullable=False)
    email = db.Column(db.Text, nullable=False)
    secret = db.Column(db.String(100))

    current_step = db.Column(db.Integer, default=0)

    public_key = db.Column(db.Text, nullable=True)  # PsifosObject: EGPublicKey
    public_key_hash = db.Column(db.String(100), nullable=True)
    secret_key = db.Column(db.Text, nullable=True)  # PsifosObject: EGSecretKey
    pok = db.Column(db.Text, nullable=True)  # PsifosObject: DLogProof

    answers_decryption_factors = db.Column(db.Text, nullable=True)  # PsifosObject: Arrayof(Arrayof(BigInteger))
    answers_decryption_proofs = db.Column(db.Text, nullable=True)  # PsifosObject: Arrayof(Arrayof(EGZKProof))
    open_answers_decryption_factors = db.Column(db.Text, nullable=True)  # PsifosObject: Arrayof(Arrayof(BigInteger))
    open_answers_decryption_proofs = db.Column(db.Text, nullable=True)  # PsifosObject: Arrayof(Arrayof(EGZKProof))

    certificate = db.Column(db.Text, nullable=True)  # PsifosObject: Certificate
    coefficients = db.Column(db.Text, nullable=True)  # PsifosObject: Coefficient
    acknowledgements = db.Column(db.Text, nullable=True)  # PsifosObject: Signature

    @classmethod
    def get_by_uuid(cls, schema, uuid, deserialize=False):
        query = cls.filter_by(schema=schema, uuid=uuid, deserialize=deserialize)
        return query[0] if len(query) > 0 else None

    @classmethod
    def get_by_login_id(cls, schema, trustee_login_id, deserialize=False):
        query = cls.filter_by(schema=schema, trustee_login_id=trustee_login_id, deserialize=deserialize)
        return query[0] if len(query) > 0 else None

    @classmethod
    def update_or_create(cls, schema, **kwargs):
        trustee = cls.get_by_uuid(
            schema=schema,
            uuid=kwargs['uuid'],
            deserialize=True,
        )
        if trustee is not None:
            for key, value in kwargs.items():
                setattr(trustee, key, value)
        else:
            trustee = cls(**kwargs)
        return trustee

    @classmethod
    def get_by_login_id_and_election(cls, schema, trustee_login_id, election_id, deserialize=False):
        query = cls.filter_by(
            schema=schema,
            trustee_login_id=trustee_login_id,
            election_id=election_id,
            deserialize=deserialize,
        )
        return query[0] if len(query) > 0 else None

    @classmethod
    def get_next_trustee_id(cls, schema, election_id):
        query = Trustee.filter_by(schema=schema, election_id=election_id)
        return 1 if len(query) == 0 else max(query, key=(lambda t: t.trustee_id)).trustee_id + 1

    @classmethod
    def get_global_trustee_step(cls, schema, election_id):
        trustee_steps = [t.current_step for t in Trustee.filter_by(schema=schema, election_id=election_id)]
        return 0 if len(trustee_steps) == 0 else min(trustee_steps)

    @classmethod
    def get_by_election(cls, schema, election_id, deserialize=False):
        return cls.filter_by(
            schema=schema,
            election_id=election_id,
            deserialize=deserialize,
        )
    
    def verify_decryption_proofs(self, election):
        """
        verifies the decryption proofs of the tally.
        """

        return election.encrypted_tally.verify_decryption_proofs(
        self.answers_decryption_factors,
        self.answers_decryption_proofs,
        self.public_key,
        fiatshamir_challenge_generator
        )



class SharedPoint(PsifosModel, db.Model):
    __table_name__ = "psifos_shared_point"

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey("psifos_election.id"))

    sender = db.Column(db.Integer, nullable=False)
    recipient = db.Column(db.Integer, nullable=False)
    point = db.Column(db.Text, nullable=True)  # SerializableField: Point

    @classmethod
    def get_by_sender(cls, schema, sender, deserialize=False,):
        query = cls.filter_by(
            schema=schema,
            sender=sender,
            deserialize=deserialize,
        )
        return query if len(query) > 0 else []

    @classmethod
    def format_points_sent_to(cls, schema, election_id, trustee_id):
        points = cls.filter_by(schema=schema, election_id=election_id, recipient=trustee_id)
        points.sort(key=(lambda x: x.sender))
        return utils.format_points(points)

    @classmethod
    def format_points_sent_by(cls, schema, election_id, trustee_id):
        points = cls.filter_by(schema=schema, election_id=election_id, sender=trustee_id)
        points.sort(key=(lambda x: x.recipient))
        return utils.format_points(points)
