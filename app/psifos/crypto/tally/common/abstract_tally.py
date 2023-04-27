"""
Abstract tally for Psifos

27-05-2022
"""

from app.database.serialization import SerializableObject
from app.psifos.crypto.elgamal import PublicKey
from app.psifos.psifos_object.questions import AbstractQuestion, QuestionFactory


class AbstractTally(SerializableObject):
    """
    This class holds the common behaviour of a question's tally;
    """
    def __init__(self, **kwargs) -> None:
        self.tally_type : str = kwargs.get("tally_type")
        self.computed : bool = kwargs.get("computed", False)
        self.num_tallied : int = int(kwargs.get("num_tallied", 0))
        self.q_num : int = int(kwargs.get("q_num", 0))
        self.num_options : int = int(kwargs.get("num_options", 0))