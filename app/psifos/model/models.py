"""
SQLAlchemy Models for Psifos.

01-04-2022
"""

from __future__ import annotations
import csv

from io import StringIO
import json

from sqlalchemy.orm import relationship
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text, Enum, DateTime, func

from app.psifos import utils
from app.psifos.psifos_object.result import ElectionResult
from app.psifos.psifos_object.questions import Questions

import app.psifos.crypto.utils as crypto_utils

from app.psifos.crypto.elgamal import ElGamal, PublicKey
from app.psifos.crypto.sharedpoint import Certificate, ListOfCoefficients, ListOfSignatures, Point
from app.psifos.crypto.utils import hash_b64
from app.psifos.crypto.tally.common.decryption.trustee_decryption import TrusteeDecryptions
from app.psifos.crypto.tally.common.encrypted_vote import EncryptedVote
from app.psifos.crypto.tally.tally import TallyManager

from app.psifos.model.enums import ElectionStatusEnum, ElectionTypeEnum

from app.database.custom_fields import SerializableField
from app.database import Base

from app.psifos_auth.model.models import User

class Election(Base):
    __tablename__ = "psifos_election"

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("auth_user.id"))
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
    voters = relationship("Voter", cascade="all, delete", backref="psifos_election")
    trustees = relationship("Trustee", cascade="all, delete", backref="psifos_election")
    sharedpoints = relationship("SharedPoint", cascade="all, delete", backref="psifos_election")
    audited_ballots = relationship("AuditedBallot", cascade="all, delete", backref="psifos_election")

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
            t=self.total_trustees // 2,
        )
        return ElGamal.serialize(params) if serialize else params

    def start(self):
        normalized_weights = [v.voter_weight / self.max_weight for v in self.voters]
        voters_by_weight_init = json.dumps({str(w): normalized_weights.count(w) for w in normalized_weights})

        start_data = {
            "voting_started_at": utils.tz_now(),
            "election_status": ElectionStatusEnum.started,
            "public_key": utils.generate_election_pk(self.trustees),
            "voters_by_weight_init": voters_by_weight_init,
        }
        return start_data

    def end(self):
        voters = [v for v in self.voters if v.cast_vote.valid_cast_votes >= 1]
        normalized_weights = [v.voter_weight / self.max_weight for v in voters]
        voters_by_weight_end = json.dumps({str(w): normalized_weights.count(w) for w in normalized_weights})

        return {
            "voting_ended_at": utils.tz_now(),
            "election_status": ElectionStatusEnum.ended,
            "voters_by_weight_end": voters_by_weight_end,
        }

    def compute_tally(self, encrypted_votes: list[EncryptedVote], weights: list[int]):
        # First we instantiate the TallyManager class.
        question_list = Questions.serialize(self.questions, to_json=False)
        pk_dict = PublicKey.serialize(self.public_key, to_json=False)
        tally_params = [
            {"tally_type": q_dict["tally_type"], "question": q_dict, "public_key": pk_dict} for q_dict in question_list
        ]

        enc_tally = TallyManager(*tally_params)

        # Then we compute the encrypted_tally
        enc_tally.compute(encrypted_votes, weights)

        return {
            "election_status": ElectionStatusEnum.tally_computed,
            "encrypted_tally": enc_tally,
            "encrypted_tally_hash": hash_b64(TallyManager.serialize(enc_tally)),
        }

    def combine_decryptions(self):
        """
        combine all of the decryption results
        """

        total_questions = len(self.encrypted_tally.get_tallies())
        partial_decryptions = [
            [
                (t.trustee_id, t.get_decryptions()[q_num].get_decryption_factors())
                for t in self.trustees
                if t.decryptions is not None
            ]
            for q_num in range(total_questions)
        ]

        return {
            "result": self.encrypted_tally.decrypt(partial_decryptions, self.total_trustees // 2, self.max_weight),
            "election_status": ElectionStatusEnum.decryptions_combined,
        }

    def voting_has_started(self):
        return True if self.voting_started_at is not None else False

    def voting_has_ended(self):
        return True if self.voting_ended_at is not None else False


class Voter(Base):
    __tablename__ = "psifos_voter"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(Integer, ForeignKey("psifos_election.id", onupdate="CASCADE", ondelete="CASCADE"))
    uuid = Column(String(50), nullable=False, unique=True)

    voter_login_id = Column(String(100), nullable=False)
    voter_name = Column(String(200), nullable=False)
    voter_weight = Column(Integer, nullable=False)

    # One-to-one relationship
    cast_vote = relationship("CastVote", cascade="all, delete", backref="psifos_voter", uselist=False)

    @staticmethod
    def upload_voters(voter_file_content: str):
        buffer = StringIO(voter_file_content)
        csv_reader = csv.reader(buffer, delimiter=",")
        voters: list[dict] = [
            {"voter_login_id": login_id, "voter_name": name, "voter_weight": weight}
            for login_id, name, weight in csv_reader
        ]
        return voters


class CastVote(Base):
    __tablename__ = "psifos_cast_vote"

    id = Column(Integer, primary_key=True, index=True)
    voter_id = Column(Integer, ForeignKey("psifos_voter.id", onupdate="CASCADE", ondelete="CASCADE"), unique=True)

    vote = Column(SerializableField(EncryptedVote), nullable=True)
    vote_hash = Column(String(500), nullable=True)
    vote_tinyhash = Column(String(500), nullable=True)

    valid_cast_votes = Column(Integer, default=0)
    invalid_cast_votes = Column(Integer, default=0)

    cast_ip = Column(Text, nullable=True)
    hash_cast_ip = Column(String(500), nullable=True)

    cast_at = Column(DateTime, nullable=True)

    def process_cast_vote(self, encrypted_vote: EncryptedVote, election: Election, voter: Voter, cast_ip: str):
        verified = encrypted_vote.verify(election)
        if verified:
            vote_fingerprint = crypto_utils.hash_b64(EncryptedVote.serialize(encrypted_vote))
            cast_at = utils.tz_now()
            ip_fingerprint = crypto_utils.hash_b64(cast_ip)
            valid_cast_votes = voter.cast_vote.valid_cast_votes + 1
            fields = {
                "voter_id": voter.id,
                "vote": encrypted_vote,
                "vote_hash": vote_fingerprint,
                "cast_at": cast_at,
                "cast_ip": cast_ip,
                "hash_cast_ip": ip_fingerprint,
                "valid_cast_votes": valid_cast_votes,
            }
        else:
            fields = {"invalid_cast_votes": voter.cast_vote.invalid_cast_votes + 1, "invalidated_at": utils.tz_now()}
        return verified, fields


class AuditedBallot(Base):
    __tablename__ = "psifos_audited_ballot"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(Integer, ForeignKey("psifos_election.id", onupdate="CASCADE", ondelete="CASCADE"))

    raw_vote = Column(Text)
    vote_hash = Column(String(500))
    added_at = Column(DateTime, default=utils.tz_now())


class Trustee(Base):
    __tablename__ = "psifos_trustee"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(Integer, ForeignKey("psifos_election.id", onupdate="CASCADE", ondelete="CASCADE"))
    trustee_id = Column(
        Integer, nullable=False
    )  # TODO: rename to index for deambiguation with trustee_id func. param at await crud.py
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

    def get_decryptions(self):
        if self.decryptions:
            return self.decryptions.instances
        return None


class SharedPoint(Base):
    __tablename__ = "psifos_shared_point"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(Integer, ForeignKey("psifos_election.id", onupdate="CASCADE", ondelete="CASCADE"))

    sender = Column(Integer, nullable=False)
    recipient = Column(Integer, nullable=False)
    point = Column(SerializableField(Point), nullable=True)


class PsifosLog(Base):
    __tablename__ = "psifos_logs"
    id = Column(Integer, primary_key=True, index=True)
    log_level = Column(String(200), nullable=False)
    log_msg = Column(String(200), nullable=False)
    created_at = Column(String(200), nullable=False)
    created_by = Column(String(200), nullable=False)
