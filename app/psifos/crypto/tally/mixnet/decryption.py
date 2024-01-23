from app.database.serialization import SerializableList
from app.psifos.crypto.tally.common.decryption.abstract_decryption import AbstractDecryption
from app.psifos.crypto.tally.mixnet.tally import MixnetTally
from app.psifos.crypto.elgamal import ListOfIntegers, ListOfZKProofs, fiatshamir_challenge_generator

class ListOfDecryptionFactors(SerializableList):
    def __init__(self, *args) -> None:
        super(ListOfDecryptionFactors, self).__init__()
        for factors_list in args:
            self.instances.append(ListOfIntegers(*factors_list))


class ListOfDecryptionProofs(SerializableList):
    def __init__(self, *args) -> None:
        super(ListOfDecryptionProofs, self).__init__()
        for proofs_list in args:
            self.instances.append(ListOfZKProofs(*proofs_list))
    


class MixnetDecryption(AbstractDecryption):
    """
    Implementation of a Trustee's partial decryption
    of an election question with an mixnet tally.

    # TODO: Implement this type of decryption.
    """
    def __init__(self, decryption_factors, decryption_proofs, **kwargs) -> None:
        super(MixnetDecryption, self).__init__(**kwargs)
        self.decryption_factors = ListOfDecryptionFactors(*decryption_factors)
        self.decryption_proofs = ListOfDecryptionProofs(*decryption_proofs)

    def _mixnet_verify(self, public_key, mixnet_tally: MixnetTally):
        tally = mixnet_tally.get_tally()
        decryption_factors = self.get_decryption_factors()
        decryption_proofs = self.get_decryption_proofs()

        # go through each one
        for vote_num, vote_ctxts in enumerate(tally):
            for choice_num, choice_ctxt in enumerate(vote_ctxts):
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
    
    def verify(self, public_key, mixnet_tally : MixnetTally):
        abstract_verify = super(MixnetDecryption, self).verify(public_key, mixnet_tally)
        mixnet_verify = self._mixnet_verify(public_key, mixnet_tally)
        return abstract_verify and mixnet_verify

    def get_decryption_factors(self):
        return [dec_factors.instances for dec_factors in self.decryption_factors.instances] 

    def get_decryption_proofs(self):
        return [dec_proofs.instances for dec_proofs in self.decryption_proofs.instances] 