from app.database import Base
from app.database.custom_fields import DLogProofField
from app.psifos.crypto.utils import random
from app.psifos.crypto.elgamal import Plaintext, fiatshamir_challenge_generator, ZKProof, DLogProof
from Crypto.Util import number
from Crypto.Hash import SHA1
from sqlalchemy import Column, Text, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.types import Integer, Text
from sqlalchemy.dialects.mysql import LONGTEXT



class PublicKey(Base):
    __tablename__ = "psifos_public_keys"

    id = Column(Integer, primary_key=True, index=True)
    _y = Column('y', Text, nullable=False)  # Usa un nombre interno para la columna en la base de datos
    _p = Column('p', Text, nullable=False)
    _g = Column('g', Text, nullable=False)
    _q = Column('q', Text, nullable=False)

    trustees = relationship("TrusteeCrypto", back_populates="public_key", uselist=False, cascade="all, delete")
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
    
class SecretKey(Base):
    __tablename__ = "psifos_secret_keys"
    id = Column(Integer, primary_key=True, index=True)
    x = Column(LONGTEXT, nullable=False)
    proof_of_knowledge = Column(DLogProofField, nullable=False)
    election_id = Column(Integer, ForeignKey("psifos_election.id", onupdate="CASCADE", ondelete="CASCADE"), nullable=False)
    election = relationship("Election", back_populates="secret_keys", cascade="all, delete")

    def __init__(self, **kwargs):
        self.x = kwargs.get('x', None)
        self.public_key = kwargs.get('public_key', None)
        self.proof_of_knowledge = kwargs.get('proof_of_knowledge', None)
        self.election_id = kwargs.get('election_id', None)

    @property
    def pk(self):
        return self.public_key
    
    @property
    def sk(self):
       return int(self.x)

    def decryption_factor(self, ciphertext, public_key):
        """
        provide the decryption factor, not yet inverted because of needed proof
        """
        return pow(ciphertext.alpha, self.sk, public_key.p)

    def decryption_factor_and_proof(self, ciphertext, public_key, challenge_generator=None):
        """
        challenge generator is almost certainly
        EG_fiatshamir_challenge_generator
        """
        if not challenge_generator:
            challenge_generator = fiatshamir_challenge_generator

        dec_factor = self.decryption_factor(ciphertext, public_key)

        proof = ZKProof.generate(public_key.g, ciphertext.alpha, self.sk, public_key.p, public_key.q, challenge_generator)

        return dec_factor, proof

    def decrypt(self, ciphertext, public_key, dec_factor = None, decode_m=False):
        """
        Decrypt a ciphertext. Optional parameter decides whether to encode the message into the proper subgroup.
        """
        if not dec_factor:
            dec_factor = self.decryption_factor(ciphertext)

        m = (number.inverse(dec_factor, public_key.p) * ciphertext.beta) % public_key.p

        if decode_m:
          # get m back from the q-order subgroup
          if m < public_key.q:
            y = m
          else:
            y = -m % public_key.p

          return y-1
        else:
          return m

    def prove_decryption(self, ciphertext):
        """
        given g, y, alpha, beta/(encoded m), prove equality of discrete log
        with Chaum Pedersen, and that discrete log is x, the secret key.

        Prover sends a=g^w, b=alpha^w for random w
        Challenge c = sha1(a,b) with and b in decimal form
        Prover sends t = w + xc

        Verifier will check that g^t = a * y^c
        and alpha^t = b * beta/m ^ c
        """
        
        m = (number.inverse(pow(ciphertext.alpha, self.x, self.pk.p), self.pk.p) * ciphertext.beta) % self.pk.p
        beta_over_m = (ciphertext.beta * number.inverse(m, self.pk.p)) % self.pk.p

        # pick a random w
        w = random.mpz_lt(self.pk.q)
        a = pow(self.pk.g, w, self.pk.p)
        b = pow(ciphertext.alpha, w, self.pk.p)

        c = int(SHA1.new(bytes(str(a) + "," + str(b), 'utf-8')).hexdigest(),16)

        t = (w + self.x * c) % self.pk.q

        return m, {
            'commitment' : {'A' : str(a), 'B': str(b)},
            'challenge' : str(c),
            'response' : str(t)
          }

    def prove_sk(self, challenge_generator):
      """
      Generate a PoK of the secret key
      Prover generates w, a random integer modulo q, and computes commitment = g^w mod p.
      Verifier provides challenge modulo q.
      Prover computes response = w + x*challenge mod q, where x is the secret key.
      """
      w = random.mpz_lt(self.pk.q)
      commitment = pow(self.pk.g, w, self.pk.p)
      challenge = challenge_generator(commitment) % self.pk.q
      response = (w + (self.x * challenge)) % self.pk.q
      
      return DLogProof(commitment, challenge, response)

class Cryptosystem(object):
    def __init__(self, **kwargs):
      self.p = kwargs.get('p', None)
      self.q = kwargs.get('q', None)
      self.g = kwargs.get('g', None)

    def generate_keypair(self):
      """
      generates a keypair in the setting
      """
      
      keypair = KeyPair()
      keypair.generate(self.p, self.q, self.g)
  
      return keypair
      
class KeyPair(object):
    def __init__(self):
      self.pk = PublicKey()
      self.sk = SecretKey()

    def generate(self, p, q, g):
      """
      Generate an ElGamal keypair
      """
      self.pk.g = g
      self.pk.p = p
      self.pk.q = q
      
      self.sk.x = random.mpz_lt(q)
      self.pk.y = pow(g, self.sk.x, p)
      
      self.sk.public_key = self.pk