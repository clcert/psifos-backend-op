from app.psifos.crypto.tally.common.encrypted_answer.abstract_enc_ans import AbstractEncryptedAnswer


class EncryptedClosedAnswer(AbstractEncryptedAnswer):
    """
    An encrypted closed answer to a single election question.
    """
    def __init__(self, **kwargs):
        super(EncryptedClosedAnswer, self).__init__(**kwargs)