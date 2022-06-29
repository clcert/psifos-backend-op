"""
Tally module for Psifos.
"""

from psifos.serialization import SerializableList
from .homomorphic.tally import HomomorphicTally
from .mixnet.tally import MixnetTally

class TallyFactory():
    @staticmethod
    def create(**kwargs):
        tally_type = kwargs.get("tally_type")
        if tally_type == "homomorphic":
            return HomomorphicTally(**kwargs)
        elif tally_type == "mixnet":
            return MixnetTally(**kwargs)
          
class TallyManager(SerializableList):
    """
    A election's tally manager that allows each question to have
    it's specific tally.
    """

    def __init__(self, *args) -> None:
        """
        Constructor of the class, instantly computes the tally. 
        """
        super(TallyManager, self).__init__()
        for tally_dict in args:
            self.instances.append(TallyFactory.create(**tally_dict))
    
    def compute(self, encrypted_votes, weights):
        for q_num, tally in enumerate(self.instances):
            encrypted_answers = [
                enc_vote.answers.instances[q_num] for enc_vote in encrypted_votes
            ]
            tally.compute(encrypted_answers=encrypted_answers, weights=weights)
    
    def decryption_factors_and_proofs(self, sk):
        decryption_factors, decryption_proofs = [], []
        for tally in self.instances:
            q_dec_f, q_dec_p = tally.decryption_factors_and_proofs(sk)
            decryption_factors.append(q_dec_f)
            decryption_proofs.append(q_dec_p)
        return decryption_factors, decryption_proofs
    
    def verify_decryption_proofs(self, decryption_factors, decryption_proofs, public_key, challenge_generator):
        for q_num, tally in enumerate(self.instances):
            verified_q =  tally.verify_decryption_proofs(
                decryption_factors[q_num],
                decryption_proofs[q_num],
                public_key,
                challenge_generator
            )

            if not verified_q:
                return False    
        return True
    
    def decrypt_from_factors(self, decryption_factors, public_key, t, max_weight=1):
        return [
            tally.decrypt_from_factors(decryption_factors[q_num], public_key, t, max_weight)
            for q_num, tally in self.instances
        ]
