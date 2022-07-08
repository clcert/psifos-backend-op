from psifos.crypto.elgamal import ListOfZKProofs, ListOfIntegers
from psifos.serialization import SerializableObject
from psifos.crypto.elgamal import fiatshamir_challenge_generator


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
