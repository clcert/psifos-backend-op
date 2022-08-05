from sqlalchemy import Boolean, Column, Integer, String
from sqlalchemy.orm import relationship

from app.database import Base

class User(Base):

    __tablename__ = "auth_user"

    id = Column(Integer, primary_key=True)

    # Id for token
    public_id = Column(String(200))
    user_type = Column(String(50))
    user_id = Column(String(100))

    username = Column(String(200), nullable=True)
    password = Column(String(200))

    # One-to-many relationship
    elections = relationship("Election", backref="auth_user")

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

