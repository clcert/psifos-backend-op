from sqlalchemy import Column, Integer, String, Text, ForeignKey, Enum, Boolean, JSON
from app.psifos.crypto.tally.common.dlogtable import DLogTable

from sqlalchemy.orm import relationship
from app.database import Base

import enum
import json

class QuestionTypeEnum(str, enum.Enum):
    CLOSED = "CLOSED"
    MIXNET = "MIXNET"
    STVNC = "STVNC"

class AbstractQuestion(Base):
    __tablename__ = "psifos_questions"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(Integer, ForeignKey("psifos_election.id", onupdate="CASCADE", ondelete="CASCADE"), nullable=False)
    index = Column(Integer, nullable=False)
    type = Column(Enum(QuestionTypeEnum), nullable=False)
    title = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    formal_options = Column(JSON, nullable=True)
    max_answers = Column(Integer, nullable=False)
    min_answers = Column(Integer, nullable=False) 
    include_informal_options = Column(String(50), nullable=True)
    tally_type = Column(String(50), nullable=False)
    grouped_options = Column(String(50), nullable=True)
    num_of_winners = Column(Integer, nullable=True)
    excluded_options = Column(Boolean, nullable=True)
    options_specifications = Column(JSON, nullable=True)
    open_option_max_size = Column(Integer, nullable=True)
    total_open_options = Column(Integer, nullable=True)

    election = relationship("Election", back_populates="questions", cascade="all, delete")
    encrypted_tally = relationship("Tally", back_populates="question")

    decryptions_homomorphic = relationship(
        "HomomorphicDecryption", cascade="all, delete", back_populates="question"
    )
    decryptions_mixnet = relationship(
        "MixnetDecryption", cascade="all, delete", back_populates="question"
    )

    TALLY_TYPE_MAP = {
        QuestionTypeEnum.CLOSED: "HOMOMORPHIC",
        QuestionTypeEnum.MIXNET: "MIXNET",
        QuestionTypeEnum.STVNC: "STVNC"
    }

    def __init__(self, *args, **kwargs):
        super(AbstractQuestion, self).__init__(*args, **kwargs)
        self.tally_type = self.TALLY_TYPE_MAP.get(self.type, "CLOSED")
    
    @property
    def total_options(self):
        """Calculate the length of formal_options if it exists, otherwise return 0."""
        if not self.formal_options:
            return 0

        informal_options_count = 2 if self.include_informal_options else 0
        return len(self.formal_options) + informal_options_count
    
    # TODO: revisar max_weight
    def decryption(self, secret_key, public_key, total_results, results_per_group=None, max_weight=1):
        """
        Perform decryption and generate proof for the encrypted tally of the question.

        Args:
            secret_key: The secret key used for decryption.
            public_key: The public key used for verification.
            max_weight: The maximum weight for precomputing the discrete log table.

        Returns:
            list: A list of dictionaries containing decryption factors, proofs, results, and group information.
        """
        results = [0] * self.total_options
        dlog_table = DLogTable(base=public_key.g, modulus=public_key.p)
        dlog_table.precompute(max_weight * max(tally.num_tallied for tally in self.encrypted_tally))

        for tally_entry in self.encrypted_tally:
            question_factors, question_proofs, result_per_group = self.process_tally_entry(tally_entry, dlog_table, secret_key, public_key)
            results = [results[i] + result_per_group[i] for i in range(len(result_per_group))]
            total_results.append(results)
            group_dict = next((item for item in results_per_group if item['group'] == tally_entry.group), None)
            if not group_dict:
                group = "Sin grupo" if tally_entry.group == "" else tally_entry.group
                results_per_group.append({
                    "group": group,
                    "results": [result_per_group],
                })
            else:
                group_dict["results"].append(result_per_group)

        return total_results, results_per_group

    def process_tally_entry(self, tally_entry, dlog_table, secret_key, public_key):
        """Process a single tally entry and return its decryption results."""
        question_factors, question_proofs = [], []
        for answer_index in range(self.total_options):
            tally = tally_entry.get_tally().instances[answer_index]
            dec_factor, proof = secret_key.decryption_factor_and_proof(tally, public_key)
            raw_value = secret_key.decrypt(tally, public_key, dec_factor)
            question_factors.append(raw_value)
            question_proofs.append(proof)
        result_per_group = [dlog_table.lookup(result) for result in question_factors]
        return question_factors, question_proofs, result_per_group