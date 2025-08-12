from sqlalchemy import Boolean, Column, Integer, String, ForeignKey, Table
from sqlalchemy.orm import relationship
from sqlalchemy.types import Enum

from app.database import Base
from app.psifos_auth.model.enums import UserRole

class User(Base):

    __tablename__ = "auth_user"

    id = Column(Integer, primary_key=True)

    # Id for token
    public_id = Column(String(200))
    user_type = Column(String(50))
    user_id = Column(String(100))

    username = Column(String(200), nullable=True)
    password = Column(String(200))

    role = Column(Enum(UserRole), nullable=False, default=UserRole.admin)

    admin_elections = relationship(
        "Election",
        secondary="psifos_election_admins",
        back_populates="admins"
    )

    def __repr__(self):
        return '<User %r>' % self.id

    def get_id(self):
        return self.id

    @classmethod
    def get_by_name(cls, name):
        query = cls.filter_by(name=name)
        return query[0] if len(query) > 0 else None

    @classmethod
    def get_by_public_id(cls, public_id):
        query = cls.filter_by(public_id=public_id)
        return query[0] if len(query) > 0 else None
    
class ElectionAdmins(Base):
    __tablename__ = "psifos_election_admins"

    election_id = Column(Integer, ForeignKey("psifos_election.id"), primary_key=True)
    user_id = Column(Integer, ForeignKey("auth_user.id"), primary_key=True)
