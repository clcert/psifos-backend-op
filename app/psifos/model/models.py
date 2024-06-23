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
from sqlalchemy.types import Boolean, Integer, String, Text, Enum, DateTime

from app.psifos import utils
from app.psifos.psifos_object.questions import Questions
from app.psifos.psifos_object.result import (
    ElectionResultManager,
    ElectionResultGroup,
)
from app.psifos.crypto.tally.common.decryption.decryption_factory import (
    DecryptionFactory,
)

import app.psifos.crypto.utils as crypto_utils

from app.psifos.crypto.elgamal import ElGamal
from app.psifos.crypto.tally.common.encrypted_vote import EncryptedVote
from app.psifos.crypto.tally.tally import TallyWrapper

from app.psifos.model.enums import ElectionStatusEnum, ElectionTypeEnum, ElectionLoginTypeEnum
from app.psifos.crypto.tally.common.decryption.trustee_decryption import TrusteeDecryptionsGroup

from app.database.custom_fields import (
    PublicKeyField,
    QuestionsField,
    TallyManagerField,
    ElectionResultField,
    EncryptedVoteField,
    CertificateField,
    TrusteeDecryptionsField,
    CoefficientsField,
    AcknowledgementsField,
    PointField,
)
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
    election_login_type =  Column(Enum(ElectionLoginTypeEnum), default="close_p")
    description = Column(Text)

    public_key = Column(PublicKeyField, nullable=True)
    questions = Column(QuestionsField, nullable=True)

    obscure_voter_names = Column(Boolean, default=False, nullable=False)
    randomize_answer_order = Column(Boolean, default=False, nullable=False)
    normalization = Column(Boolean, default=False, nullable=False)
    grouped = Column(Boolean, default=False, nullable=False)
    max_weight = Column(Integer, nullable=False)

    total_voters = Column(Integer, default=0)
    total_trustees = Column(Integer, default=0)

    encrypted_tally = Column(TallyManagerField, nullable=True)
    encrypted_tally_hash = Column(Text, nullable=True)

    decryptions_uploaded = Column(Integer, default=0)
    result = Column(ElectionResultField, nullable=True)

    voting_started_at = Column(DateTime, nullable=True)
    voting_ended_at = Column(DateTime, nullable=True)

    voters_by_weight_init = Column(Text, nullable=True)
    voters_by_weight_end = Column(Text, nullable=True)

    # One-to-many relationships
    voters = relationship("Voter", cascade="all, delete",
                          backref="psifos_election")
    trustees = relationship(
        "TrusteeCrypto", cascade="all, delete", backref="psifos_election")
    sharedpoints = relationship(
        "SharedPoint", cascade="all, delete", backref="psifos_election"
    )
    audited_ballots = relationship(
        "AuditedBallot", cascade="all, delete", backref="psifos_election"
    )

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

    def start(self):
        normalized_weights = {}
        voters_by_weight_init = {}
        for v in self.voters:
            v_g = v.group
            v_w = v.voter_weight / self.max_weight
            normalized_weights.setdefault(v_g, []).append(v_w)
            voters_by_weight_init[v_w] = voters_by_weight_init.get(v_w, 0) + 1

        voters_by_weight_init_grouped = [
            {"group": group, "weights": {
                str(w): weights_group.count(w) for w in weights_group}}
            for group, weights_group in normalized_weights.items()
        ]

        weight_init = json.dumps({
            "voters_by_weight_init": voters_by_weight_init,
            "voters_by_weight_init_grouped": voters_by_weight_init_grouped
        })

        return {
            "voting_started_at": utils.tz_now(),
            "election_status": ElectionStatusEnum.started,
            "public_key": utils.generate_election_pk(self.trustees),
            "voters_by_weight_init": weight_init,
        }

    def end(self):
        voters = [v for v in self.voters if v.valid_cast_votes >= 1]
        voters_by_weight_end = {}
        normalized_weights = {}
        for v in voters:
            v_w = v.voter_weight / self.max_weight
            v_g = v.group
            normalized_weights.setdefault(v_g, []).append(v_w)
            voters_by_weight_end[v_w] = voters_by_weight_end.get(v_w, 0) + 1

        voters_by_weight_end_grouped = [
            {"group": group, "weights": {
                str(w): weights_group.count(w) for w in weights_group}}
            for group, weights_group in normalized_weights.items()
        ]

        weight_end = json.dumps({
            "voters_by_weight_end": voters_by_weight_end,
            "voters_by_weight_end_grouped": voters_by_weight_end_grouped
        })

        return {
            "voting_ended_at": utils.tz_now(),
            "election_status": ElectionStatusEnum.ended,
            "voters_by_weight_end": weight_end,
        }

    def compute_tally(
        self, encrypted_votes: list[EncryptedVote], weights: list[int], group: str
    ):
        # First we instantiate the TallyManager class.
        question_list = Questions.serialize(self.questions, to_json=False)
        tally_params = [
            {
                "tally_type": q_dict["tally_type"],
                "computed": False,
                "num_tallied": 0,
                "q_num": q_num,
                "max_answers": q_dict["max_answers"],
                "num_options": q_dict["total_closed_options"],
                "num_of_winners": q_dict.get("num_of_winners", None),
                "include_blank_null": q_dict["include_blank_null"] == "True",
            }
            for q_num, q_dict in enumerate(question_list)
        ]
        with_votes = len(encrypted_votes) > 0
        enc_tally = TallyWrapper(
            *tally_params, group=group, with_votes=with_votes)

        # Then we compute the encrypted_tally
        enc_tally.compute(
            encrypted_votes=encrypted_votes, weights=weights, election=self
        )

        return enc_tally

    def combine_decryptions(self):
        """
        combine all of the decryption results
        """
        result_per_group = []
        results_total = []
        for tally in self.encrypted_tally.get_tallys():
            with_votes = tally.get("with_votes", False) == "True"
            group = tally.get("group", "")
            tally_dict = tally.get("tally")
            total_questions = len(tally_dict)
            if with_votes:
                partial_decryptions = [
                    [
                        (
                            t.trustee_id,
                            DecryptionFactory.create(
                                **utils.from_json(TrusteeDecryptionsGroup.serialize(t.get_decryptions_group(group))).get("decryptions")[
                                    q_num
                                ]
                            ).get_decryption_factors(),
                        )
                        for t in self.trustees
                        if t.decryptions is not None
                    ]
                    for q_num in range(total_questions)
                ]
                tally = TallyWrapper(*tally_dict, group=group, with_votes=True)
                group = group if group else "Sin grupo"
                results_grouped = tally.decrypt(
                    partial_decryptions=partial_decryptions,
                    election=self,
                    group=group,
                )
                result_per_group.append(results_grouped)
                for index, result in enumerate(results_grouped.result.instances):
                    if len(results_total) == index:
                        results_total.append(
                            {"ans_results": result.ans_results.instances})
                    else:
                        results_total[index]["ans_results"] = [
                            a + b for a, b in zip(result.ans_results.instances, results_total[index]["ans_results"])
                        ]
            else:
                result_dict = [{"ans_results": dic["tally"]}
                               for dic in tally_dict]
                if len(results_total) == 0:
                    results_total = [{"ans_results": [
                        int(value) for value in array_result["tally"]]} for array_result in tally_dict]
                group = group if group else "Sin grupo"
                result_per_group.append(ElectionResultGroup(
                    *result_dict, group=group, with_votes=with_votes))

        return {"result": ElectionResultManager(results_total=results_total, results_grouped=result_per_group), "election_status": ElectionStatusEnum.decryptions_combined}

    def end_without_votes(self, groups):
        question_list = Questions.serialize(self.questions, to_json=False)
        groups.append("Sin grupo")
        results = []
        results_group = []
        for group in groups:
            aux_group_results = []
            for question in question_list:
                result_question = {
                        "tally_type": question["tally_type"],
                        "ans_results": ["0"] * int(question["total_closed_options"]),
                    }
                aux_group_results.append(
                    result_question
                )
            results = aux_group_results
            results_group.append(
                ElectionResultGroup(
                    *aux_group_results, group=group, with_votes=False)
            )
        election_result = ElectionResultManager(results_total=results, results_grouped=results_group)
        return {
            "result": election_result,
            "election_status": ElectionStatusEnum.decryptions_combined,
        }

    def results_released(self):
        released_data = {
            "election_status": ElectionStatusEnum.results_released,
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
    uuid = Column(String(50), nullable=False, unique=True)

    voter_login_id = Column(String(100), nullable=False)
    voter_name = Column(String(200), nullable=False)
    voter_weight = Column(Integer, nullable=False)

    valid_cast_votes = Column(Integer, default=0)
    invalid_cast_votes = Column(Integer, default=0)

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
                    "voter_login_id": voter[0],
                    "voter_name": voter[1],
                    "voter_weight": voter[2],
                    "group": voter[3] if add_group else ""
                }
            )
        return voters

    def process_cast_vote(
        self, encrypted_vote: EncryptedVote, election: Election, cast_ip: str
    ):
        is_valid = encrypted_vote.verify(election)
        cast_vote_fields = {
            "vote": encrypted_vote,
            "vote_hash": crypto_utils.hash_b64(EncryptedVote.serialize(encrypted_vote)),
            "is_valid": is_valid,
            "cast_ip": cast_ip,
            "cast_ip_hash": crypto_utils.hash_b64(cast_ip),
            "cast_at": utils.tz_now(),
        }

        voter_fields = {}
        if is_valid:
            voter_fields["valid_cast_votes"] = self.valid_cast_votes + 1
        else:
            voter_fields["invalid_cast_votes"] = self.invalid_cast_votes + 1

        return is_valid, voter_fields, cast_vote_fields


class CastVote(Base):
    __tablename__ = "psifos_cast_vote"

    id = Column(Integer, primary_key=True, index=True)
    voter_id = Column(
        Integer,
        ForeignKey("psifos_voter.id", onupdate="CASCADE", ondelete="CASCADE"),
        unique=True,
    )

    vote = Column(EncryptedVoteField, nullable=False)
    vote_hash = Column(String(500), nullable=False)
    # vote_tinyhash = Column(String(500), nullable=False)

    is_valid = Column(Boolean, nullable=False)

    cast_ip = Column(Text, nullable=False)
    cast_ip_hash = Column(String(500), nullable=False)

    cast_at = Column(DateTime, nullable=False)


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
    uuid = Column(String(50), nullable=False, unique=True)

    name = Column(String(200), nullable=False)
    trustee_login_id = Column(String(100), nullable=False, unique=True)
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

    current_step = Column(Integer, default=0)

    public_key = Column(PublicKeyField, nullable=True)
    public_key_hash = Column(String(100), nullable=True)
    decryptions = Column(TrusteeDecryptionsField, nullable=True)

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

    created_at = Column(String(200), nullable=False)
