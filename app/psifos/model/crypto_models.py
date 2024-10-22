from sqlalchemy import Column, Text, Integer
from sqlalchemy.orm import relationship
from app.database import Base


class PublicKey(Base):
    __tablename__ = "psifos_public_keys"

    id = Column(Integer, primary_key=True, index=True)
    _y = Column('y', Text, nullable=False)  # Usa un nombre interno para la columna en la base de datos
    _p = Column('p', Text, nullable=False)
    _g = Column('g', Text, nullable=False)
    _q = Column('q', Text, nullable=False)

    trustees = relationship("Trustee", back_populates="public_key", uselist=False, cascade="all, delete")
    elections = relationship("Election", back_populates="public_key", uselist=False, cascade="all, delete")

    @property
    def y(self):
        return int(self._y)

    @y.setter
    def y(self, value):
        self._y = str(value)

    @property
    def p(self):
        return int(self._p)

    @p.setter
    def p(self, value):
        self._p = str(value)

    @property
    def g(self):
        return int(self._g)

    @g.setter
    def g(self, value):
        self._g = str(value)

    @property
    def q(self):
        return int(self._q)

    @q.setter
    def q(self, value):
        self._q = str(value)
    
    def __repr__(self):
        return f"PublicKey(id={self.id}, y={self.y}, p={self.p}, g={self.g}, q={self.q})"
    
    def to_dict(self):
        return {
            'id': str(self.id),
            'y': (self._y),
            'p': (self._p),
            'g': (self._g),
            'q': (self._q)
        }

    def __mul__(self, other):
        if other == 0 or other == 1:
            return self

        # check p and q
        if self.p != other.p or self.q != other.q or self.g != other.g:
            raise Exception("incompatible public keys")

        params = {
            "p": self.p,
            "q": self.q,
            "g": self.g,
            "y": (self.y * other.y) % self.p,
        }
        return PublicKey(**params)

    def clone_with_new_y(self, y):
        params = {
            "p": self.p,
            "q": self.q,
            "g": self.g,
            "y": y % self.p
        }
        return PublicKey(**params)