from app.psifos.crypto.elgamal import ListOfZKProofs, ListOfNestedIntegers, fiatshamir_challenge_generator
from app.psifos.crypto.tally.common.decryption.abstract_decryption import AbstractDecryption
from app.psifos.crypto.tally.homomorphic.tally import HomomorphicTally


class HomomorphicDecryption(AbstractDecryption):
    """
    Implementation of a Trustee's partial decryption
    of an election question with an homomorphic tally.
    """
    def __init__(self, decryption_factors, decryption_proofs, **kwargs) -> None:
        super(HomomorphicDecryption, self).__init__(**kwargs)
        self.decryption_factors = ListOfNestedIntegers(*decryption_factors)
        self.decryption_proofs = ListOfZKProofs(*decryption_proofs)

    
    def _homomorphic_verify(self, public_key, homomorphic_tally: HomomorphicTally):
        tally = homomorphic_tally.tally

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
        abstract_verify = super(HomomorphicDecryption, self).verify(public_key, homomorphic_tally)
        homomorphic_verify = self._homomorphic_verify(public_key, homomorphic_tally)
        return abstract_verify and homomorphic_verify

    def get_decryption_factors(self):
        return self.decryption_factors.instances
    
    def get_decryption_proofs(self):
        return self.decryption_proofs.instances
