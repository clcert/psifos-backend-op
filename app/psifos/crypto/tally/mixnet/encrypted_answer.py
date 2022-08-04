from app.psifos.crypto.elgamal import Ciphertext
from app.psifos.crypto.tally.common.encrypted_answer.abstract_enc_ans import AbstractEncryptedAnswer


class EncryptedOpenAnswer(AbstractEncryptedAnswer):
    """
    An encrypted open answer to a single election question.
    """
    def __init__(self, **kwargs) -> None:
        self.open_answer : Ciphertext = Ciphertext(**kwargs["open_answer"])
        super(EncryptedOpenAnswer, self).__init__(**kwargs)