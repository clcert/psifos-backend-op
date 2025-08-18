"""
SQLAlchemy Models for Psifos.

01-04-2022
"""

from __future__ import annotations
import csv

from io import StringIO
import json

from sqlalchemy.orm import relationship
from sqlalchemy import Column, ForeignKey
from sqlalchemy.types import Boolean, Integer, String, Text, Enum, DateTime, JSON

from app.psifos import utils

import app.psifos.crypto.utils as crypto_utils
from app.psifos.model.cruds import crypto_crud

from app.psifos.crypto.elgamal import ElGamal
from app.psifos.crypto.tally.common.encrypted_vote import EncryptedVote
from app.psifos.crypto.tally.tally import TallyWrapper, TallyFactory

from app.psifos.model.enums import ElectionStatusEnum, ElectionTypeEnum, ElectionLoginTypeEnum, TrusteeStepEnum
from app.psifos.crypto.tally.common.decryption.trustee_decryption import TrusteeDecryptionsGroup

from app.database.custom_fields import (
    EncryptedVoteField,
    CertificateField,
    TrusteeDecryptionsField,
    CoefficientsField,
    AcknowledgementsField,
    PointField,
)
from app.database import Base
from app.psifos_auth.model.models import User
from app.psifos.model.questions import AbstractQuestion  # Importar la clase de pregunta
from app.psifos.model.crypto_models import PublicKey
from app.psifos.model.results import Results
from app.psifos.model.tally import Tally, HomomorphicTally, MixnetTally, STVTally
from app.psifos.model.decryptions import HomomorphicDecryption, MixnetDecryption

class Election(Base):
    __tablename__ = "psifos_election"

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("auth_user.id"))

    short_name = Column(String(50), nullable=False, unique=True)
    long_name = Column(String(150), nullable=False)
    type = Column(Enum(ElectionTypeEnum), nullable=False)
    status = Column(Enum(ElectionStatusEnum), default="setting_up")
    voters_login_type =  Column(Enum(ElectionLoginTypeEnum), default="close_p")
    description = Column(Text)
    
    public_key_id = Column(Integer, ForeignKey("psifos_public_keys.id", ondelete="CASCADE"), nullable=True, unique=True)
    public_key = relationship("PublicKey", back_populates="elections", uselist=False, cascade="all, delete")

    questions = relationship("AbstractQuestion", cascade="all, delete", back_populates="election")

    randomized_options = Column(Boolean, default=False, nullable=False)
    normalized = Column(Boolean, default=False, nullable=False)
    grouped_voters = Column(Boolean, default=False, nullable=False)
    max_weight = Column(Integer, nullable=False)

    decryptions_uploaded = Column(Integer, default=0)

    result = relationship("Results",uselist=False, cascade="all, delete", backref="psifos_election")


    # One-to-many relationships
    voters = relationship("Voter", cascade="all, delete",
                          backref="psifos_election")
    trustees = relationship(
        "TrusteeCrypto", cascade="all, delete", backref="psifos_election")
    sharedpoints = relationship(
        "SharedPoint", cascade="all, delete", backref="psifos_election"
    ) # TODO: Check 
    audited_ballots = relationship(
        "AuditedBallot", cascade="all, delete", backref="psifos_election"
    )

    @property
    def total_trustees(self):
        return len(self.trustees)
    
    @property
    def decryptions_uploaded(self):
        sent_decryptions_trustees = [t for t in self.trustees if t.current_step == TrusteeStepEnum.decryptions_sent]
        return len(sent_decryptions_trustees)
    
    @property
    def total_questions(self):
        return len(self.questions)

    def get_eg_params(self, serialize=True):
        """
        Returns the current election params for elgamal encryption.

        If serialize==False, returns an instance of psfios.crypto.elgamal.ElGamal
        else, returns the instance serialized as a JSON
        """

        homomorphic_params = ElGamal(
            p=16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071,
            q=61329566248342901292543872769978950870633559608669337131139375508370458778917,
            g=14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533,
            l=self.total_trustees,
            t=self.total_trustees // 2,
        )

        mixnet_params = ElGamal(
            p=18327991482361669004286639798074385949400820527508693038281793842419658778646183172043714372434887662397495316046424276660244274945405969876809123683433321250545108479986526816070819839957965107425628145736191837131508884754895750146570877651437107861199128784596337922813704126294239514133764359696513958683035290336886031265046191900273191001058569366746816268635864575581741352326134814483409332935713546125268177796076176035462970215700537486727982100562697116663646391349282042978452419214916303106449995547276153571886404788957113873880035926652300634390083324146443946720486724627744466059746347363887763313743,
            q=9163995741180834502143319899037192974700410263754346519140896921209829389323091586021857186217443831198747658023212138330122137472702984938404561841716660625272554239993263408035409919978982553712814072868095918565754442377447875073285438825718553930599564392298168961406852063147119757066882179848256979341517645168443015632523095950136595500529284683373408134317932287790870676163067407241704666467856773062634088898038088017731485107850268743363991050281348558331823195674641021489226209607458151553224997773638076785943202394478556936940017963326150317195041662073221973360243362313872233029873173681943881656871,
            g=16141898911809788492463153022431594386168319330222751768493351040952735565361896626024447515650922389607562504530451845501876091151301288417170631825455184588835325157781438398677204184012389811003436159787883489522402724138691780356199397916889317025148963039437773815193899568773625897337438669015395689510555217519657274498167109193026516201153157184411632736242491162216511771478776845530382144041894008864963974005512677070493327538989029656740352284939727572199971495877462619563754716116212378070273900583647050080189064355617936261153568358447985978219381341970181603196085481796711486639560779759080607611174,
            l=self.total_trustees,
            t=self.total_trustees // 2,
        )

        params = {
            "homomorphic_params": ElGamal.serialize(homomorphic_params)
            if serialize
            else homomorphic_params,
            "mixnet_params": ElGamal.serialize(mixnet_params)
            if serialize
            else mixnet_params,
        }

        return params
    
    def ready_key_generation(self):
        if not self.questions:
            return False, "No questions found in the election"
        
        if not self.trustees:
            return False, "No trustees found in the election"
        
        if self.voters_login_type == ElectionLoginTypeEnum.close_p and not self.voters:
            return False, "No voters found in the election"
        
        return True, "The election is ready for key generation"
    
    def ready_opening(self):
        not_ready_trustees = [t.trustee.name for t in self.trustees if t.current_step != TrusteeStepEnum.waiting_decryptions]
        if not_ready_trustees:
            return False, f"Trustees not ready to open the election: {', '.join(not_ready_trustees)}"
        return True, "The election is ready to be opened"
    
    def ready_opening_public_vote(self):
        if not self.questions:
            return False, "No questions found in the election"
        return True, "The election is ready to be opened"

    async def start(self, session):

        if self.type != ElectionTypeEnum.public_vote_election:

            election_pk = await utils.generate_election_pk(self.trustees, session)
            pk = await crypto_crud.create_public_key(
                session=session,
                public_key=election_pk
            )

            return {
                "status": ElectionStatusEnum.started,
                "public_key_id": pk.id,
            }
        
        return {
            "status": ElectionStatusEnum.started,
        }

    def end(self):

        return {
            "status": ElectionStatusEnum.ended,
        }

    def compute_tally(
        self, encrypted_votes: list[EncryptedVote], weights: list[int], public_key: dict, with_votes: bool = True, group: str = ""
    ):
        question_list = self.questions
        tally_array = []

        for q_num, question in enumerate(question_list):
            tally_object = TallyFactory.create(
                tally_type=question.tally_type,
                computed=False,
                num_tallied=0,
                question_id=question.id,
                question=question,
            )

            if with_votes:
                encrypted_answers = [enc_vote.answers.instances[q_num] for enc_vote in encrypted_votes]
                tally_object.compute(
                    public_key=public_key,
                    encrypted_answers=encrypted_answers,
                    weights=weights,
                    election=self,
                    width=question.max_answers
                )
            else:
                tally_object.encrypted_tally = json.dumps([0] * question.total_options)

            tally_array.append(tally_object)

        return tally_array

    def combine_decryptions(self, session, tallies):
        """
        combine all of the decryption results
        """
        from app.celery_worker.psifos.model import crud

        def get_partial_decryptions(trustees, total_questions, group):
            return [
                [
                    (t.trustee_election_id, crud.get_decryptions_by_trustee_id(session, t.id, q_num + 1, group).get_decryption_factors())
                    for t in trustees
                ]
                for q_num in range(total_questions)
            ]

        public_key = self.public_key
        result_per_group = []
        results_total = []

        # Iteramos sobre el tally total
        for tally_object in tallies:
            group = tally_object[0].group
            total_questions = len(self.questions)
            group = group if group else "Sin grupo"

            if tally_object[0].with_votes:
                trustee_with_decryptions = [t for t in self.trustees if t.current_step == TrusteeStepEnum.decryptions_sent]
                partial_decryptions = get_partial_decryptions(trustee_with_decryptions, total_questions, tally_object[0].group)
                decrypted_tally = [
                    tally.decrypt(
                        public_key=public_key,
                        decryption_factors=partial_decryptions[q_num],
                        t=self.total_trustees // 2,
                        max_weight=self.max_weight,
                    )
                    for q_num, tally in enumerate(tally_object)
                ]
                result_per_group.append({"result": decrypted_tally, "group": group})

                for index, result in enumerate(decrypted_tally):
                    if len(results_total) == index:
                        results_total.append(result)
                    else:
                        results_total[index] = [
                            a + b for a, b in zip(result, results_total[index])
                        ]
            else:
                result_dict = [dic.get_loads_tally() for dic in tally_object]
                if not results_total:
                    results_total = [
                        [int(value) for value in array_result.get_loads_tally()]
                        for array_result in tally_object
                    ]

                result_per_group.append({"result": result_dict, "group": group})

        return {"total_result": results_total, "grouped_result": result_per_group}

    def end_without_votes(self, groups: list, questions: list) -> dict:
        groups.append("Sin grupo")
        results = []
        results_group = []
        for group in groups:
            aux_group_results = []
            for question in questions:
                result_question = {
                        "ans_results": [0] * int(question.total_options),
                    }
                aux_group_results.append(
                    result_question["ans_results"]
                )
            results = aux_group_results
            results_group.append({
                "result": aux_group_results,
                "group": group
            })

        return {"total_result": results, "grouped_result": results_group}

    def results_released(self):
        released_data = {
            "status": ElectionStatusEnum.results_released,
        }
        return released_data

    def voting_has_started(self):
        return True if self.voting_started_at is not None else False

    def voting_has_ended(self):
        return True if self.voting_ended_at is not None else False


class Voter(Base):
    __tablename__ = "psifos_voter"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(
        Integer,
        ForeignKey("psifos_election.id",
                   onupdate="CASCADE", ondelete="CASCADE"),
    )
    username = Column(String(100), nullable=False)
    name = Column(String(200), nullable=False)

    username_election_id = Column(String(50), nullable=False, unique=True)
    weight_init = Column(Integer, nullable=False)
    weight_end = Column(Integer, nullable=True)

    group = Column(String(200), nullable=True)
    # One-to-one relationship
    cast_vote = relationship(
        "CastVote", cascade="all, delete", backref="psifos_voter", uselist=False
    )

    @staticmethod
    def upload_voters(voter_file_content: str, grouped: bool):
        buffer = StringIO(voter_file_content)
        csv_reader = csv.reader(buffer, delimiter=",")
        voters: list[dict] = []
        for voter in csv_reader:
            add_group = len(voter) > 3 and grouped
            voters.append(
                {
                    "username": voter[0],
                    "voter_name": voter[1],
                    "voter_weight": voter[2],
                    "group": voter[3] if add_group else ""
                }
            )
        return voters

    def process_cast_vote(
        self, encrypted_vote: EncryptedVote, election: Election, public_key: PublicKey, questions: AbstractQuestion
    ):
        is_valid = encrypted_vote.verify(election, public_key, questions=questions)
        cast_vote_fields = {
            "encrypted_ballot": encrypted_vote,
            "encrypted_ballot_hash": crypto_utils.hash_b64(EncryptedVote.serialize(encrypted_vote)),
            "is_valid": is_valid,
            "cast_at": utils.tz_now(),
        }
        return is_valid, cast_vote_fields
    
    async def has_valid_vote(self, session):
        from app.psifos.model.cruds import crud
        return await crud.has_valid_vote(session=session, election_id=self.election_id, username=self.username)


class CastVote(Base):
    __tablename__ = "psifos_cast_vote"

    id = Column(Integer, primary_key=True, index=True)
    voter_id = Column(
        Integer,
        ForeignKey("psifos_voter.id", onupdate="CASCADE", ondelete="CASCADE"),
        unique=True,
    )

    encrypted_ballot = Column(EncryptedVoteField, nullable=False)
    encrypted_ballot_hash = Column(String(500), nullable=False)

    is_valid = Column(Boolean, nullable=False)
    cast_at = Column(DateTime, nullable=False)

class Vote(Base):
    __tablename__ = "psifos_vote"

    id = Column(Integer, primary_key=True, index=True)
    voter_id = Column(
        Integer,
        ForeignKey("psifos_voter.id",
                   onupdate="CASCADE", ondelete="CASCADE"),
    )

    vote = Column(JSON, nullable=False)
    is_valid = Column(Boolean, nullable=False)
    cast_at = Column(DateTime, default=utils.tz_now())

class AuditedBallot(Base):
    __tablename__ = "psifos_audited_ballot"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(
        Integer,
        ForeignKey("psifos_election.id",
                   onupdate="CASCADE", ondelete="CASCADE"),
    )

    raw_vote = Column(Text)
    vote_hash = Column(String(500))
    added_at = Column(DateTime, default=utils.tz_now())


class Trustee(Base):
    __tablename__ = "psifos_trustee"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(String(200), nullable=False)
    username = Column(String(100), nullable=False, unique=True)
    email = Column(Text, nullable=False)
    trustee_crypto = relationship(
        "TrusteeCrypto", cascade="all, delete",
        back_populates="trustee"
    ) 

class TrusteeCrypto(Base):
    __tablename__ = "psifos_trustee_crypto"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(
        Integer,
        ForeignKey("psifos_election.id",
                   onupdate="CASCADE", ondelete="CASCADE"),
    )
    trustee_id = Column(
        Integer,
        ForeignKey("psifos_trustee.id",
                   onupdate="CASCADE", ondelete="CASCADE"),
    )

    trustee_election_id = Column(
        Integer, nullable=False
    )  # TODO: rename to index for deambiguation with trustee_id func. param at await crud.py

    current_step = Column(Enum(TrusteeStepEnum), default="config_step")

    public_key = relationship("PublicKey", back_populates="trustees", uselist=False, single_parent=True)
    public_key_id = Column(Integer, ForeignKey("psifos_public_keys.id"), nullable=True, unique=True)

    public_key_hash = Column(String(100), nullable=True)
    decryptions_homomorphic = relationship(
        "HomomorphicDecryption", cascade="all, delete", back_populates="trustee_crypto"
    )
    decryptions_mixnet = relationship(
        "MixnetDecryption", cascade="all, delete", back_populates="trustee_crypto"
    )
    certificate = Column(CertificateField, nullable=True)
    coefficients = Column(CoefficientsField, nullable=True)
    acknowledgements = Column(AcknowledgementsField, nullable=True)

    trustee = relationship("Trustee", back_populates="trustee_crypto")

    def get_decryptions_group(self, group):
        if self.decryptions:
            decryptions_group = filter(
                lambda dic: dic.group == group, self.decryptions.instances
            )
            return next(decryptions_group)
        return None

class SharedPoint(Base):
    __tablename__ = "psifos_shared_point"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(
        Integer,
        ForeignKey("psifos_election.id",
                   onupdate="CASCADE", ondelete="CASCADE"),
    )

    sender = Column(Integer, nullable=False)
    recipient = Column(Integer, nullable=False)
    point = Column(PointField, nullable=True)


class ElectionLog(Base):
    __tablename__ = "election_logs"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(
        Integer,
        ForeignKey("psifos_election.id",
                   onupdate="CASCADE", ondelete="CASCADE"),
    )

    log_level = Column(String(200), nullable=False)

    event = Column(String(200), nullable=False)
    event_params = Column(String(200), nullable=False)

    created_at = Column(DateTime, default=utils.tz_now())
