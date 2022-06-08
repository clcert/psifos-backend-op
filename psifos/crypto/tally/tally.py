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
            tally.compute(encrypted_answers=encrypted_votes[q_num], weights=weights)