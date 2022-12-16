from app.psifos.crypto.elgamal import ZKDisjunctiveProof
from app.psifos.crypto.elgamal import ListOfZKDisjunctiveProofs
from app.psifos.crypto.tally.common.encrypted_answer.abstract_enc_ans import AbstractEncryptedAnswer


class EncryptedClosedAnswer(AbstractEncryptedAnswer):
    """
    An encrypted closed answer to a single election question.
    """
    def __init__(self, **kwargs):
        super(EncryptedClosedAnswer, self).__init__(**kwargs)
        self.individual_proofs : ListOfZKDisjunctiveProofs = ListOfZKDisjunctiveProofs(*kwargs["individual_proofs"])
        self.overall_proof : ZKDisjunctiveProof = ZKDisjunctiveProof(*kwargs["overall_proof"])