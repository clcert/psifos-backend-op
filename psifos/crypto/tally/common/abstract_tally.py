"""
Abstract tally for Psifos

27-05-2022
"""

class AbstractTally(object):
    """
    This class holds the common behaviour of a question's tally;
    """
    def __init__(self, *args, **kwargs) -> None:
        self.tally_type = kwargs.get("tally_type")
        self.num_tallied = kwargs.get("num_tallied", 0)