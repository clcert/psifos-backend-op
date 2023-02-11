"""
Tally module for Psifos.
"""

from app.database.serialization import SerializableList
from app.psifos.psifos_object.result import ElectionResult
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
    
    def compute(self, encrypted_votes, weights, public_key, election_name, election_uuid):
        for q_num, tally in enumerate(self.instances):
            encrypted_answers = [
                enc_vote.answers.instances[q_num] for enc_vote in encrypted_votes
            ]

            tally.compute(encrypted_answers=encrypted_answers, weights=weights, public_key=public_key, 
                          election_name=election_name, election_uuid=election_uuid)
    
    def decryption_factors_and_proofs(self, sk):
        decryption_factors, decryption_proofs = [], []
        for tally in self.instances:
            q_dec_f, q_dec_p = tally.decryption_factors_and_proofs(sk)
            decryption_factors.append(q_dec_f)
            decryption_proofs.append(q_dec_p)
        return decryption_factors, decryption_proofs
    
    def decrypt(self, partial_decryptions, t, max_weight=1, questions=[]):
        return ElectionResult(*[
            tally.decrypt(partial_decryptions[q_num], t, max_weight=max_weight, 
            total_closed_options=questions.instances[q_num].total_closed_options)
            for q_num, tally in enumerate(self.instances)
        ])
    
    def get_tallies(self):
        return self.instances
