from sqlalchemy import Column, Integer, String, Text, ForeignKey, Enum, Boolean, JSON
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