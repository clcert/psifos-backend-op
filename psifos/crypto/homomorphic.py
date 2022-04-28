"""
Ballot crypto classes for Psifos.

14-04-2022
"""
from psifos.serialization import SerializableObject

class EncryptedAnswer(SerializableObject):
    pass


class EncryptedVote(SerializableObject):
    pass


class EncryptedVoteWithRandomness(SerializableObject):
    pass


class Tally(SerializableObject):
    pass