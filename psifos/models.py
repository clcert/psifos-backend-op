"""
SQLAlchemy Models for Psifos.

01-04-2022
"""

from __future__ import annotations

import datetime
import functools
import json
from psifos.crypto.utils import hash_b64

import psifos.utils as utils
from psifos import db
from psifos.crypto.elgamal import (DecryptionFactors, DecryptionProofs,
                                   ElGamal, PublicKey,
                                   fiatshamir_challenge_generator)
from psifos.crypto.sharedpoint import (Certificate, ListOfCoefficients,
                                       ListOfSignatures, Point)
from psifos.crypto.tally.common.encrypted_vote import EncryptedVote
from psifos.crypto.tally.tally import TallyManager
from psifos.custom_fields.enums import ElectionStatusEnum, ElectionTypeEnum
from psifos.custom_fields.sqlalchemy import SerializableField
from psifos.psifos_auth.models import User
from psifos.psifos_model import PsifosModel
from psifos.psifos_object.questions import Questions


class Election(PsifosModel, db.Model):
    __tablename__ = "psifos_election"

    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('auth_user.id'))
    uuid = db.Column(db.String(50), nullable=False, unique=True)

    short_name = db.Column(db.String(100), nullable=False, unique=True)
    name = db.Column(db.String(250), nullable=False)
    election_type = db.Column(db.Enum(ElectionTypeEnum), nullable=False)
    election_status = db.Column(db.Enum(ElectionStatusEnum), default="setting_up")
    private_p = db.Column(db.Boolean, default=False, nullable=False)
    description = db.Column(db.Text)

    public_key = db.Column(SerializableField(PublicKey), nullable=True)
    private_key = db.Column(db.Text, nullable=True)  # PsifosObject: EGSecretKey
    questions = db.Column(SerializableField(Questions), nullable=True)
    openreg = db.Column(db.Boolean, default=False)

    obscure_voter_names = db.Column(db.Boolean, default=False, nullable=False)
    randomize_answer_order = db.Column(db.Boolean, default=False, nullable=False)
    normalization = db.Column(db.Boolean, default=False, nullable=False)
    max_weight = db.Column(db.Integer, nullable=False)

    total_voters = db.Column(db.Integer, default=0)
    total_trustees = db.Column(db.Integer, default=0)

    cast_url = db.Column(db.String(500))
    encrypted_tally = db.Column(SerializableField(TallyManager), nullable=True)
    encrypted_tally_hash = db.Column(db.Text, nullable=True)
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
        self.votes_by_weight_final = json.dumps({str(w):normalized_weights.count(w) for w in normalized_weights})
        
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

        total_questions = len(self.encrypted_tally.tally)
        partial_decryptions = [
            [
                (t.trustee_id, t.get_decryptions()[q_num]) 
                for t in trustees if t.answers_decryptions is not None
            ]
            for q_num in range(total_questions)
        ]

        self.result = self.encrypted_tally.decrypt(partial_decryptions, self.total_trustees//2, self.max_weight)
        print(self.result)

    
    def get_tallies(self):
        if self.encrypted_tally:
            return self.encrypted_tally.instances
        return None

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
    

class CastVote(PsifosModel, db.Model):
    __table_name__ = "psifos_cast_vote"

    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.Integer, db.ForeignKey("psifos_voter.id"), unique=True)
    
    vote = db.Column(SerializableField(EncryptedVote), nullable=True)
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

    public_key = db.Column(SerializableField(PublicKey), nullable=True)
    public_key_hash = db.Column(db.String(100), nullable=True)
    secret_key = db.Column(db.Text, nullable=True)  # PsifosObject: EGSecretKey
    pok = db.Column(db.Text, nullable=True)  # PsifosObject: DLogProof

    answers_decryptions = db.Column(SerializableField(TrusteeDecryptions), nullable=True)

    certificate = db.Column(SerializableField(Certificate), nullable=True)
    coefficients = db.Column(SerializableField(ListOfCoefficients), nullable=True)
    acknowledgements = db.Column(SerializableField(ListOfSignatures), nullable=True)

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
        if self.answers_decryptions:
            return self.answers_decryptions.instances
        return None



class SharedPoint(PsifosModel, db.Model):
    __table_name__ = "psifos_shared_point"

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey("psifos_election.id"))

    sender = db.Column(db.Integer, nullable=False)
    recipient = db.Column(db.Integer, nullable=False)
    point = db.Column(SerializableField(Point), nullable=True)

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
