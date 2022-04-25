"""
ElGamal encryption classes for Psifos.

14-04-2022.
"""
from psifos.serialization import SerializableObject

class EGParams(SerializableObject):
    pass


class EGPublicKey(SerializableObject):
    pass


class EGSecretKey(SerializableObject):
    pass


class EGCiphertext(SerializableObject):
    pass


class EGZKProofCommitment(SerializableObject):
    pass


class EGZKProof(SerializableObject):
    pass


class EGZKDisjunctiveProof(SerializableObject):
    pass


class DLogProof:
    pass

class DecryptionFactors:
    pass

class DecryptionProofs:
    pass