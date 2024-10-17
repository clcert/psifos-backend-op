from sqlalchemy import Column, Integer, JSON, Enum, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base

from app.psifos.crypto.elgamal import ListOfZKProofs, ListOfIntegers, fiatshamir_challenge_generator
from app.psifos.crypto.tally.homomorphic.tally import HomomorphicTally
from app.psifos.crypto.tally.mixnet.decryption import ListOfDecryptionFactors, ListOfDecryptionProofs

from app.database.custom_fields import ListOfDecryptionFactorsField, ListOfDecryptionProofsField, ListOfIntegersField, ListOfZKProofsField


class DecryptionFactory:
    """
    Factory class to create the corresponding decryption object
    based on the type of tally.
    """

    @staticmethod
    def create_decryption(decryption_type, decryption_factors, decryption_proofs, **kwargs):
        decryption_type = decryption_type.lower()
        if decryption_type == "homomorphic":
            return HomomorphicDecryption(decryption_factors, decryption_proofs, decryption_type **kwargs)
        elif decryption_type == "mixnet":
            return MixnetDecryption(decryption_factors, decryption_proofs, decryption_type, **kwargs)
        else:
            raise ValueError("Invalid decryption type")

class HomomorphicDecryption(Base):
    """
    Implementation of a Trustee's partial decryption
    of an election question with an homomorphic tally.
    """

    __tablename__ = "psifos_decryptions_homomorphic"

    id = Column(Integer, primary_key=True, index=True)
    trustee_id = Column(Integer, ForeignKey("psifos_trustee.id"), nullable=False)
    group = Column(Text, nullable=False)
    q_num = Column(Integer, nullable=False)

    psifos_trustee = relationship("Trustee", back_populates="decryptions_homomorphic", cascade="all, delete")
    decryption_factors = Column(ListOfIntegersField, nullable=True)
    decryption_proofs = Column(ListOfZKProofsField, nullable=True)

    def __init__(self, decryption_factors, decryption_proofs, decryption_type, **kwargs) -> None:
        super(HomomorphicDecryption, self).__init__(**kwargs)
        self.decryption_factors = ListOfIntegers(*decryption_factors) if type(decryption_factors) == list else decryption_factors
        self.decryption_proofs = ListOfZKProofs(*decryption_proofs) if type(decryption_proofs) == list else decryption_proofs
        self.decryption_type = decryption_type

    def get_factor_object(self):
        return self.decryption_factors
    
    def get_proof_object(self):
        return self.decryption_proofs

    def _homomorphic_verify(self, public_key, homomorphic_tally):
        tally = homomorphic_tally.get_tally()

        # go through each one
        for a_num, ans_tally in enumerate(tally.instances):
            proof = self.decryption_proofs.instances[a_num]
            factor = self.decryption_factors.instances[a_num]

            # check that g, alpha, y, dec_factor is a DH tuple
            verify_params = {
                "little_g" : public_key.g,
                "little_h" : ans_tally.alpha,
                "big_g" : public_key.y,
                "big_h" : factor,
                "p" : public_key.p,
                "challenge_generator" : fiatshamir_challenge_generator
            }
            if not proof.verify(**verify_params):
                return False

        return True

    def verify(self, public_key, homomorphic_tally : HomomorphicTally):
        homomorphic_verify = self._homomorphic_verify(public_key, homomorphic_tally)
        return homomorphic_verify

    def get_decryption_factors(self):
        return self.decryption_factors.instances
    
    def get_decryption_proofs(self):
        return self.decryption_proofs.instances

class MixnetDecryption(Base):
    """
    Implementation of a Trustee's partial decryption
    of an election question with an mixnet tally.

    # TODO: Implement this type of decryption.
    """

    __tablename__ = "psifos_decryptions_mixnet"

    id = Column(Integer, primary_key=True, index=True)
    trustee_id = Column(Integer, ForeignKey("psifos_trustee.id"), nullable=False)
    group = Column(Text, nullable=False)
    q_num = Column(Integer, nullable=False)

    psifos_trustee = relationship("Trustee", back_populates="decryptions_mixnet", cascade="all, delete")
    decryption_factors = Column(ListOfDecryptionFactorsField, nullable=True)
    decryption_proofs = Column(ListOfDecryptionProofsField, nullable=True)

    def __init__(self, decryption_factors, decryption_proofs, decryption_type, **kwargs) -> None:
        super(MixnetDecryption, self).__init__(**kwargs)
        self.decryption_factors = ListOfDecryptionFactors(*decryption_factors)
        self.decryption_proofs = ListOfDecryptionProofs(*decryption_proofs)
        self.decryption_type = decryption_type

    def _mixnet_verify(self, public_key, mixnet_tally):
        tally = mixnet_tally.get_tally()
        decryption_factors = self.get_decryption_factors()
        decryption_proofs = self.get_decryption_proofs()
        # go through each one
        for vote_num, vote_ctxts in enumerate(tally.instances):
            for choice_num, choice_ctxt in enumerate(vote_ctxts.instances):
                proof = decryption_proofs[vote_num][choice_num]
                factor = decryption_factors[vote_num][choice_num]

                # check that g, alpha, y, dec_factor is a DH tuple
                verify_params = {
                    "little_g" : public_key.g,
                    "little_h" : choice_ctxt.alpha,
                    "big_g" : public_key.y,
                    "big_h" : factor,
                    "p" : public_key.p,
                    "challenge_generator" : fiatshamir_challenge_generator
                }
                if not proof.verify(**verify_params):
                    return False

        return True
    
    def verify(self, public_key, mixnet_tally):
        mixnet_verify = self._mixnet_verify(public_key, mixnet_tally)
        return mixnet_verify

    def get_decryption_factors(self):
        return [dec_factors.instances for dec_factors in self.decryption_factors.instances] 

    def get_decryption_proofs(self):
        return [dec_proofs.instances for dec_proofs in self.decryption_proofs.instances] 
