"""
Tally module for Psifos.
"""

from app.database.serialization import SerializableList, SerializableObject
from .homomorphic.tally import HomomorphicTally
from .mixnet.close_massive_tally import CloseMassiveTally
from .mixnet.stv_tally import STVTally


class TallyFactory:
    @staticmethod
    def create(**kwargs):
        tally_to_mn_tally = {
            "CLOSED":HomomorphicTally,
            "MIXNET":CloseMassiveTally,
            "STVNC":STVTally,
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
            self.instances.append(tally_dict)

    def get_by_group(self, group):
        encrypted_tally_group = filter(
            lambda dic: dic.get("group") == group, self.instances
        )
        return next(encrypted_tally_group, None)

    def get_tallys(self):
        if self.instances:
            return self.instances
        return None


class TallyWrapper(SerializableObject):
    def __init__(self, *args, **kwargs) -> None:
        """
        Constructor of the class, instantly computes the tally.
        """
        super(TallyWrapper, self).__init__()
        self.group: str = kwargs.get("group", "")
        self.with_votes: bool = kwargs.get("with_votes")
        self.tally = ListOfTallies(*args)

    def compute(self, encrypted_votes, weights, election, public_key):

        for q_num, tally in enumerate(self.tally.instances):
            encrypted_answers = [
                enc_vote.answers.instances[q_num] for enc_vote in encrypted_votes
            ]
            width = election.questions[q_num].max_answers
            tally.compute(
                public_key=public_key,
                encrypted_answers=encrypted_answers,
                weights=weights,
                election=election,
                width=width
            )

    def decrypt(self, partial_decryptions, election, group):
        public_key = (
            election.public_key
        )  # TODO: replace this when multiple pk gets added

        decrypted_tally = []
        for q_num, tally in enumerate(self.tally.instances):
            decrypted_tally.append(
                tally.decrypt(
                    public_key=public_key,
                    decryption_factors=partial_decryptions[q_num],
                    t=election.total_trustees // 2,
                    max_weight=election.max_weight,
                ),
            )
        return {"result": decrypted_tally, "group":group}

    def get_tallies(self):
        return self.tally.instances


class ListOfTallies(SerializableList):
    def __init__(self, *args) -> None:
        super(ListOfTallies, self).__init__()
        for tally_dict in args:
            self.instances.append(TallyFactory.create(**tally_dict))
