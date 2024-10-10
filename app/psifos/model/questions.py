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
    election_id = Column(Integer, ForeignKey("psifos_election.id"), nullable=False)
    q_num = Column(Integer, nullable=False)
    q_type = Column(Enum(QuestionTypeEnum), nullable=False)
    q_text = Column(Text, nullable=False)
    q_description = Column(Text, nullable=True)
    total_options = Column(Integer, nullable=False)
    total_closed_options = Column(Integer, nullable=False)
    closed_options = Column(Text, nullable=True)
    max_answers = Column(Integer, nullable=False)
    min_answers = Column(Integer, nullable=False)
    include_blank_null = Column(String(50), nullable=True)
    tally_type = Column(String(50), nullable=False)
    group_votes = Column(String(50), nullable=True)
    num_of_winners = Column(Integer, nullable=True)
    excluding_groups = Column(Boolean, nullable=True)
    options_specifications = Column(JSON, nullable=True)
    open_option_max_size = Column(Integer, nullable=True)
    total_open_options = Column(Integer, nullable=True)

    election = relationship("Election", back_populates="questions")

    TALLY_TYPE_MAP = {
        QuestionTypeEnum.CLOSED: "HOMOMORPHIC",
        QuestionTypeEnum.MIXNET: "MIXNET",
        QuestionTypeEnum.STVNC: "STVNC"
    }

    def __init__(self, *args, **kwargs):
        super(AbstractQuestion, self).__init__(*args, **kwargs)
        self.tally_type = self.TALLY_TYPE_MAP.get(self.q_type, "CLOSED")

    @property
    def closed_options_list(self):
        return json.loads(self.closed_options) if self.closed_options else []

    @closed_options_list.setter
    def closed_options_list(self, value):
        self.closed_options = json.dumps(value)
