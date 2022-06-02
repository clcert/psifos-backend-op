"""
Tally module for Psifos.
"""

from os import stat
from psifos.crypto.elgamal import PublicKey

from psifos.serialization import SerializableList, SerializableObject
from .homomorphic.tally import HomomorphicTally
from .mixnet.tally import MixnetTally

class TallyFactory():
    @staticmethod
    def create(question):
        tally_type = question["tally_type"]
        if tally_type == "homomorphic":
            return HomomorphicTally(question)
        elif tally_type == "mixnet":
            return MixnetTally(question)


class ListOfTallies(SerializableList):
    def __init__(self, *args) -> None:
        super(ListOfTallies, self).__init__()
        for q in args:
            self.instances.append(TallyFactory.create())
            
class TallyManager(SerializableObject):
    """
    A election's tally manager that allows each question to have
    it's specific tally.
    """

    def __init__(self, public_key, questions, casted_votes) -> None:
        """
        Constructor of the class, instantly computes the tally. 
        """

        # creates tallies of questions
        self.tallies : SerializableList = ListOfTallies(*questions)

        # loads public_key to each tally
        self.__load_pk(public_key)

        # loads votes to each tally
        self.__load_votes(casted_votes)

    def get_instances(self):
        return self.__tallies.instances

    def __load_pk(self, public_key):
        """loads public_key to each tally"""
        for tally in self.tallies.instances:
            tally.public_key = public_key

    def __load_votes(self, casted_votes):
        """loads votes to each tally"""
        for tally in self.tallies.instances:
            tally.add_votes(casted_votes)

    def compute(self, election):
        # magia...
        pass