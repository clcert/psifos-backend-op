"""
Tally module for Psifos.
"""

from app.database.serialization import SerializableList
from app.psifos.psifos_object.result import ElectionResult
from .homomorphic.tally import HomomorphicTally
from .mixnet.close_massive_tally import CloseMassiveTally
from .mixnet.stv_tally import STVTally

class TallyFactory():
    @staticmethod
    def create(**kwargs):
        tally_to_mn_tally = {
            "homomorphic":HomomorphicTally,
            "mixnet":CloseMassiveTally,
            "stvnc":STVTally,
        }
        tally_type = kwargs.get("tally_type")
        if tally_type in tally_to_mn_tally.keys():
            return tally_to_mn_tally[tally_type](**kwargs)
          
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
    
    def compute(self, encrypted_votes, weights, election):
        public_key = election.public_key    # TODO: replace this when multiple pk gets added

        for q_num, tally in enumerate(self.instances):
            encrypted_answers = [
                enc_vote.answers.instances[q_num] for enc_vote in encrypted_votes
            ]

            tally.compute(
                public_key=public_key,
                encrypted_answers=encrypted_answers,
                weights=weights,
                election=election
            )
    
    def decrypt(self, partial_decryptions, election):
        public_key = election.public_key    # TODO: replace this when multiple pk gets added
        
        decrypted_tally = []
        for q_num, tally in enumerate(self.instances):
            decrypted_tally.append(
                tally.decrypt(
                    public_key=public_key,
                    decryption_factors=partial_decryptions[q_num],
                    t=election.total_trustees//2,
                    max_weight=election.max_weight
                )
            )
        
        return ElectionResult(*decrypted_tally)
    
    def get_tallies(self):
        return self.instances
