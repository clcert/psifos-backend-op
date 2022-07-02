"""
Abstract tally for Psifos

27-05-2022
"""

from psifos.crypto.elgamal import PublicKey
from psifos.psifos_object.questions import AbstractQuestion, QuestionFactory
from psifos.serialization import SerializableObject


class AbstractTally(SerializableObject):
    """
    This class holds the common behaviour of a question's tally;
    """
    def __init__(self, **kwargs) -> None:
        self.tally_type : str = kwargs.get("tally_type")
        self.computed : bool = kwargs.get("computed", False)
        self.num_tallied : int = int(kwargs.get("num_tallied", 0))
        self.question : AbstractQuestion = QuestionFactory.create(**kwargs.get("question"))
        self.public_key : PublicKey = PublicKey(**kwargs.get("public_key"))