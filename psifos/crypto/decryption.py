from psifos.crypto.elgamal import ListOfZKProofs, ListOfIntegers
from psifos.crypto.tally.homomorphic.tally import HomomorphicTally
from psifos.crypto.tally.mixnet.tally import MixnetTally
from psifos.serialization import SerializableList, SerializableObject
from psifos.crypto.elgamal import fiatshamir_challenge_generator


class TrusteeDecryptions(SerializableList):
    def __init__(self, *args) -> None:
        super(TrusteeDecryptions, self).__init__()
        for decryption_dict in args:
            self.instances.append(DecryptionFactory.create(**decryption_dict))
    
    def verify(self, encrypted_tally):
        tallies = encrypted_tally.get_tallies()
        for tally, decryption in zip(tallies, self.instances):
            question_verify = decryption.verify(tally)
            if not question_verify:
                return False
        return True


class DecryptionFactory():
    @staticmethod
    def create(**kwargs):
        tally_type = kwargs.get("tally_type")
        if tally_type == "homomorphic":
            return HomomorphicDecryption(**kwargs)
        elif tally_type == "mixnet":
            return MixnetDecryption(**kwargs)
        else:
            return None


class AbstractDecryption(SerializableObject):
    """
    Holds the common behaviour of a Trustee's partial decryption
    for a question with an arbitrary tally_type.
    """
    def __init__(self, tally_type, decryption_factors, decryption_proofs) -> None:
        self.tally_type = tally_type
        self.decryption_factors = ListOfIntegers(*decryption_factors)
        self.decryption_proofs = ListOfZKProofs(*decryption_proofs)

    def verify(self, a_tally):
        """
        Verifies the decryption proofs of a tally.
        """
        public_key = a_tally.public_key
        tally = a_tally.tally

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

    def get_decryption_factors(self):
        return self.decryption_factors.instances
    
    def get_decryption_proofs(self):
        return self.decryption_proofs.instances


class HomomorphicDecryption(AbstractDecryption):
    """
    Implementation of a Trustee's partial decryption
    of an election question with an homomorphic tally.
    """
    def __init__(self, **kwargs) -> None:
        super(HomomorphicDecryption, self).__init__(**kwargs)

    def verify(self, homomorphic_tally : HomomorphicTally):
        abstract_verify = super(HomomorphicDecryption, self).verify(homomorphic_tally)
        # new verifications ?
        return abstract_verify


class MixnetDecryption(AbstractDecryption):
    """
    Implementation of a Trustee's partial decryption
    of an election question with an mixnet tally.

    # TODO: Implement this type of decryption.
    """
    def __init__(self, **kwargs) -> None:
        super(MixnetDecryption, self).__init__(**kwargs)
    
    def verify(self, mixnet_tally : MixnetTally):
        abstract_verify = super(MixnetDecryption, self).verify(mixnet_tally)
        # new verifications ?
        return abstract_verify


