from app.psifos.crypto.elgamal import Ciphertext
from app.psifos.crypto.tally.common.encrypted_answer.abstract_enc_ans import AbstractEncryptedAnswer
from app.config import MIXNET_WIDTH


class EncryptedOpenAnswer(AbstractEncryptedAnswer):
    """
    An encrypted open answer to a single election question.
    """
    def __init__(self, **kwargs) -> None:
        self.open_answer : Ciphertext = Ciphertext(**kwargs["open_answer"])
        super(EncryptedOpenAnswer, self).__init__(**kwargs)

class EncryptedMixnetAnswer(AbstractEncryptedAnswer):
    """
    An encrypted mixnet answer to a single election question.
    """
    def __init__(self, **kwargs) -> None:
        super(EncryptedMixnetAnswer, self).__init__(**kwargs)
    
    def verify(self, **kwargs):
        max_ptxt = kwargs.get('max_ptxt')
        return len(self.get_choices()) == max_ptxt

class EncryptedStvncAnswer(AbstractEncryptedAnswer):
    """
    An encrypted mixnet answer to a single election question.
    """
    def __init__(self, **kwargs) -> None:
        super(EncryptedStvncAnswer, self).__init__(**kwargs)
    
    def verify(self, **kwargs):
        max_ptxt = kwargs.get('max_ptxt')
        return len(self.get_choices()) == max_ptxt
    