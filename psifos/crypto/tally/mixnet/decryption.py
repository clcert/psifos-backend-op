from psifos.crypto.tally.common.decryption.abstract_decryption import AbstractDecryption
from psifos.crypto.tally.mixnet.tally import MixnetTally


class MixnetDecryption(AbstractDecryption):
    """
    Implementation of a Trustee's partial decryption
    of an election question with an mixnet tally.

    # TODO: Implement this type of decryption.
    """
    def __init__(self, **kwargs) -> None:
        super(MixnetDecryption, self).__init__(**kwargs)
    
    def verify(self, mixnet_tally : MixnetTally):
        abstract_verify = super(MixnetDecryption, self).verify(mixnet_tally)
        # new verifications ?
        return abstract_verify