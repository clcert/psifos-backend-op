"""
Mixnet tally for psifos questions.

27-05-2022
"""

from ..common.abstract_tally import AbstractTally

class MixnetTally(AbstractTally):
    """
    Mixnet tally implementation for open questions.
    """
    def __init__(self, *args, **kwargs) -> None:
        super(MixnetTally, self).__init__(*args, **kwargs)
        # TODO: implement MixnetTally.