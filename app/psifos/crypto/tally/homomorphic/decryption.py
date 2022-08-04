from app.psifos.crypto.tally.common.decryption.abstract_decryption import AbstractDecryption
from app.psifos.crypto.tally.homomorphic.tally import HomomorphicTally


class HomomorphicDecryption(AbstractDecryption):
    """
    Implementation of a Trustee's partial decryption
    of an election question with an homomorphic tally.
    """
    def __init__(self, **kwargs) -> None:
        super(HomomorphicDecryption, self).__init__(**kwargs)

    def verify(self, homomorphic_tally : HomomorphicTally):
        abstract_verify = super(HomomorphicDecryption, self).verify(homomorphic_tally)
        # new verifications ?
        return abstract_verify