"""
Encrypted answer for Psifos vote.

27-05-2022
"""

from app.database.serialization import SerializableObject
from app.psifos.crypto.elgamal import ListOfCipherTexts

class AbstractEncryptedAnswer(SerializableObject):
    def __init__(self, **kwargs) -> None:
        self.enc_ans_type = kwargs["enc_ans_type"]
        self.choices : ListOfCipherTexts = ListOfCipherTexts(*kwargs["choices"])

    def get_choices(self):
        return self.choices.instances
