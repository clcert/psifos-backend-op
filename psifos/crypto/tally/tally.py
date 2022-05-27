"""
Tally module for Psifos.
"""

from .homomorphic.tally import HomomorphicTally, Tally
from .mixnet.tally import MixnetTally

class TallyManager():
    def create(self, tally_type):
        if tally_type == "homomorphic":
            return HomomorphicTally()
        elif tally_type == "mixnet":
            return MixnetTally()

    def compute(self, questions, encrypted_votes):
        tallies = [self.create(q.tally_type) for q in questions]
        # magia con los encrypted votes ...


tally = TallyManager()
