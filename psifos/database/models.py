"""
SQLAlchemy Models for Psifos.

01-04-2022
"""

from __future__ import annotations

import datetime
import functools
import json
from psifos.psifos_object.result import ElectionResult

import psifos.utils as utils
from psifos.crypto.tally.common.decryption.trustee_decryption import TrusteeDecryptions
from psifos.crypto.elgamal import ElGamal, PublicKey
from psifos.crypto.sharedpoint import (Certificate, ListOfCoefficients,
                                       ListOfSignatures, Point)
from psifos.crypto.tally.common.encrypted_vote import EncryptedVote
from psifos.crypto.tally.tally import TallyManager
from psifos.crypto.utils import hash_b64
from psifos.database.enums import ElectionStatusEnum, ElectionTypeEnum
from psifos.database.custom_fields import SerializableField
from psifos.psifos_auth.models import User
from psifos.psifos_model import PsifosModel
from psifos.psifos_object.questions import Questions

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text, Enum, DateTime, func
from sqlalchemy.orm import relationship

from . import Base


class Election(PsifosModel, Base):
    __tablename__ = "psifos_election"

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey('auth_user.id'))
    uuid = Column(String(50), nullable=False, unique=True)

    short_name = Column(String(100), nullable=False, unique=True)
    name = Column(String(250), nullable=False)
    election_type = Column(Enum(ElectionTypeEnum), nullable=False)
    election_status = Column(Enum(ElectionStatusEnum), default="setting_up")
    private_p = Column(Boolean, default=False, nullable=False)
    description = Column(Text)

    public_key = Column(SerializableField(PublicKey), nullable=True)
    private_key = Column(Text, nullable=True)  # PsifosObject: EGSecretKey
    questions = Column(SerializableField(Questions), nullable=True)

    obscure_voter_names = Column(Boolean, default=False, nullable=False)
    randomize_answer_order = Column(Boolean, default=False, nullable=False)
    normalization = Column(Boolean, default=False, nullable=False)
    max_weight = Column(Integer, nullable=False)

    total_voters = Column(Integer, default=0)
    total_trustees = Column(Integer, default=0)

    cast_url = Column(String(500))
    encrypted_tally = Column(SerializableField(TallyManager), nullable=True)
    encrypted_tally_hash = Column(Text, nullable=True)

    decryptions = Column(SerializableField(TrusteeDecryptions), nullable=True)
    decryptions_uploaded = Column(Integer, default=0)
    result = Column(SerializableField(ElectionResult), nullable=True)

    voting_started_at = Column(DateTime, nullable=True)
    voting_ended_at = Column(DateTime, nullable=True)
    
    voters_by_weight_init = Column(Text, nullable=True)
    voters_by_weight_end = Column(Text, nullable=True)


    # One-to-many relationships
    voters = relationship("Voter", backref="psifos_election")
    trustees = relationship("Trustee", backref="psifos_election")
    sharedpoints = relationship("SharedPoint", backref="psifos_election")
    audited_ballots = relationship("AuditedBallot", backref="psifos_election")

    def __repr__(self):
        return '<Election %r>' % self.name

    @classmethod
    def get_by_short_name(cls, short_name) -> Election:
        query = cls.filter_by(short_name=short_name)
        return query[0] if len(query) > 0 else None

    @classmethod
    def get_by_uuid(cls, uuid):
        query = cls.filter_by(uuid=uuid)
        return query[0] if len(query) > 0 else None

    @classmethod
    def update_or_create(cls, **kwargs):
        election = cls.get_by_uuid(
            uuid=kwargs['uuid']
        )
        if election is not None:
            for key, value in kwargs.items():
                setattr(election, key, value)
        else:
            election = cls(**kwargs)
        
        PsifosModel.add(election)
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
        self.election_status = "started"

        a_combined_pk = trustees[0].coefficients.instances[0].coefficient
        for t in trustees[1:]:
            a_combined_pk = combined_pk * t.coefficients.instances[0].coefficient

        t_first_coefficients = [t.coefficients.instances[0].coefficient for t in trustees]
        
        combined_pk = functools.reduce((lambda x, y: x*y), t_first_coefficients)
        self.public_key = trustees[0].public_key.clone_with_new_y(combined_pk)

        normalized_weights = [v.voter_weight / self.max_weight for v in voters]
        self.voters_by_weight_init = json.dumps({str(w):normalized_weights.count(w) for w in normalized_weights})
        
        PsifosModel.add(self)
        PsifosModel.commit()
    
    def end(self, voters):
        self.voting_ended_at = datetime.datetime.utcnow()
        self.election_status = "ended"

        normalized_weights = [v.voter_weight / self.max_weight for v in voters]
        self.voters_by_weight_end = json.dumps({str(w):normalized_weights.count(w) for w in normalized_weights})
        
        PsifosModel.add(self)
        PsifosModel.commit()


    def compute_tally(self, encrypted_votes, weights):
        # First we instantiate the TallyManager class.
        question_list = Questions.serialize(self.questions, to_json=False)
        pk_dict = PublicKey.serialize(self.public_key, to_json=False)
        tally_params = [{
            "tally_type": q_dict["tally_type"],
            "question": q_dict,
            "public_key": pk_dict
        } for q_dict in question_list]

        enc_tally = TallyManager(*tally_params)

        # Then we compute the encrypted_tally
        enc_tally.compute(encrypted_votes, weights)
        
        self.election_status = "tally_computed"
        self.encrypted_tally = enc_tally
        self.encrypted_tally_hash = hash_b64(TallyManager.serialize(enc_tally))

        PsifosModel.add(self)
        PsifosModel.commit()

    def combine_decryptions(self, trustees):
        """
        combine all of the decryption results
        """

        total_questions = len(self.encrypted_tally.get_tallies())
        partial_decryptions = [
            [
                (t.trustee_id, t.get_decryptions()[q_num].get_decryption_factors()) 
                for t in trustees if t.decryptions is not None
            ]
            for q_num in range(total_questions)
        ]

        self.result = self.encrypted_tally.decrypt(partial_decryptions, self.total_trustees//2, self.max_weight)
        self.election_status = "decryptions_combined"
        PsifosModel.add(self)
        PsifosModel.commit()


    def current_num_casted_votes(self):
        voters = Voter.get_by_election(election_id=self.id)
        return len([v for v in voters if v.cast_vote.valid_cast_votes >= 1])
    
    def voting_has_started(self):
        return True if self.voting_started_at is not None else False
    
    def voting_has_ended(self):
        return True if self.voting_ended_at is not None else False

class Voter(PsifosModel, Base):
    __tablename__ = "psifos_voter"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(Integer, ForeignKey('psifos_election.id'))
    uuid = Column(String(50), nullable=False, unique=True)

    voter_login_id = Column(String(100), nullable=False)
    voter_name = Column(String(200), nullable=False)
    voter_weight = Column(Integer, nullable=False)

    # One-to-one relationship
    cast_vote = relationship("CastVote", cascade="delete", backref="psifos_voter", uselist=False)

    @classmethod
    def get_by_login_id_and_election(cls, voter_login_id, election_id):
        query = cls.filter_by(
            voter_login_id=voter_login_id,
            election_id=election_id
        )
        return query[0] if len(query) > 0 else None

    @classmethod
    def update_or_create(cls, **kwargs):
        voter = cls.get_by_login_id_and_election(
            voter_login_id=kwargs["voter_login_id"],
            election_id=kwargs["election_id"]
        )
        if voter is not None:
            for key, value in kwargs.items():
                setattr(voter, key, value)
        else:
            voter = cls(**kwargs)

        PsifosModel.add(voter)
        return voter
    
    @classmethod
    def get_by_election(cls, election_id):
        return cls.filter_by(election_id=election_id)
    

class CastVote(PsifosModel, Base):
    __table_name__ = "psifos_cast_vote"

    id = Column(Integer, primary_key=True, index=True)
    voter_id = Column(Integer, ForeignKey("psifos_voter.id"), unique=True)
    
    vote = Column(SerializableField(EncryptedVote), nullable=True)
    vote_hash = Column(String(500), nullable=True)
    vote_tinyhash = Column(String(500), nullable=True)

    valid_cast_votes = Column(Integer, default=0)
    invalid_cast_votes = Column(Integer, default=0)
    
    cast_ip = Column(Text, nullable=True)
    hash_cast_ip = Column(String(500), nullable=True)
    
    cast_at = Column(DateTime, default=func.now(), nullable=True)
    verified_at = Column(DateTime, nullable=True)
    invalidated_at = Column(DateTime, nullable=True)

    @classmethod
    def get_by_voter_id(cls, voter_id):
        query = cls.filter_by(voter_id=voter_id)
        return query[0] if len(query) > 0 else None

    @classmethod
    def update_or_create(cls, **kwargs):
        cast_vote = cls.get_by_voter_id(voter_id=kwargs["voter_id"])
        if cast_vote is not None:
            for key, value in kwargs.items():
                setattr(cast_vote, key, value)
        else:
            cast_vote = cls(**kwargs)

        PsifosModel.add(cast_vote)
        return cast_vote
    


class AuditedBallot(PsifosModel, Base):
    __table_name__ = "psifos_audited_ballot"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(Integer, ForeignKey("psifos_election.id"))

    raw_vote = Column(Text)
    vote_hash = Column(String(500))
    added_at = Column(DateTime, default=func.now())


class Trustee(PsifosModel, Base):
    __table_name__ = "psifos_trustee"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(Integer, ForeignKey("psifos_election.id"))
    trustee_id = Column(Integer, nullable=False)
    uuid = Column(String(50), nullable=False, unique=True)

    name = Column(String(200), nullable=False)
    trustee_login_id = Column(String(100), nullable=False)
    email = Column(Text, nullable=False)
    secret = Column(String(100))

    current_step = Column(Integer, default=0)

    public_key = Column(SerializableField(PublicKey), nullable=True)
    public_key_hash = Column(String(100), nullable=True)
    secret_key = Column(Text, nullable=True)  # PsifosObject: EGSecretKey
    pok = Column(Text, nullable=True)  # PsifosObject: DLogProof

    decryptions = Column(SerializableField(TrusteeDecryptions), nullable=True)

    certificate = Column(SerializableField(Certificate), nullable=True)
    coefficients = Column(SerializableField(ListOfCoefficients), nullable=True)
    acknowledgements = Column(SerializableField(ListOfSignatures), nullable=True)

    @classmethod
    def get_by_uuid(cls, uuid):
        query = cls.filter_by(uuid=uuid)
        return query[0] if len(query) > 0 else None

    @classmethod
    def get_by_login_id(cls, trustee_login_id):
        query = cls.filter_by(trustee_login_id=trustee_login_id)
        return query[0] if len(query) > 0 else None

    @classmethod
    def update_or_create(cls, **kwargs):
        trustee = cls.get_by_uuid(uuid=kwargs['uuid'])
        if trustee is not None:
            for key, value in kwargs.items():
                setattr(trustee, key, value)
        else:
            trustee = cls(**kwargs)

        PsifosModel.add(trustee)
        return trustee

    @classmethod
    def get_by_login_id_and_election(cls, trustee_login_id, election_id):
        query = cls.filter_by(
            trustee_login_id=trustee_login_id,
            election_id=election_id
        )
        return query[0] if len(query) > 0 else None

    @classmethod
    def get_next_trustee_id(cls, election_id):
        query = Trustee.filter_by(election_id=election_id)
        return 1 if len(query) == 0 else max(query, key=(lambda t: t.trustee_id)).trustee_id + 1

    @classmethod
    def get_global_trustee_step(cls, election_id):
        trustee_steps = [t.current_step for t in Trustee.filter_by(election_id=election_id)]
        return 0 if len(trustee_steps) == 0 else min(trustee_steps)

    @classmethod
    def get_by_election(cls, election_id):
        return cls.filter_by(election_id=election_id)

    def get_decryptions(self):
        if self.decryptions:
            return self.decryptions.instances
        return None



class SharedPoint(PsifosModel, Base):
    __table_name__ = "psifos_shared_point"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(Integer, ForeignKey("psifos_election.id"))

    sender = Column(Integer, nullable=False)
    recipient = Column(Integer, nullable=False)
    point = Column(SerializableField(Point), nullable=True)

    @classmethod
    def get_by_sender(cls, sender):
        query = cls.filter_by(
            sender=sender
        )
        return query if len(query) > 0 else []

    @classmethod
    def format_points_sent_to(cls, election_id, trustee_id):
        points = cls.filter_by(election_id=election_id, recipient=trustee_id)
        points.sort(key=(lambda x: x.sender))
        return utils.format_points(points)

    @classmethod
    def format_points_sent_by(cls, election_id, trustee_id):
        points = cls.filter_by(election_id=election_id, sender=trustee_id)
        points.sort(key=(lambda x: x.recipient))
        return utils.format_points(points)
