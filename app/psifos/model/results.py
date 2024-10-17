from sqlalchemy import Column, Integer, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base

class Results(Base):
    __tablename__ = "psifos_results"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(Integer, ForeignKey("psifos_election.id"), nullable=False, unique=True)
    total_result = Column(JSON, nullable=False)
    grouped_result = Column(JSON, nullable=True)

    election = relationship("Election", back_populates="result", cascade="all, delete")

    def __init__(self, *args, **kwargs):
        super(Results, self).__init__(*args, **kwargs)

