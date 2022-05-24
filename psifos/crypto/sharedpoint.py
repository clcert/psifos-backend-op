"""
SharedPoint classes for Psifos.

14-04-2022
"""

from psifos.serialization import SerializableList, SerializableObject
from psifos.crypto.utils import BigInteger


class Signature(SerializableObject):
    def __init__(self, challenge, response) -> None:
        self.challenge: BigInteger = BigInteger(challenge)
        self.response: BigInteger = BigInteger(response)


class Certificate(SerializableObject):
    def __init__(self, signature_key, encryption_key, signature) -> None:
        self.signature_key: BigInteger = BigInteger(signature_key)
        self.encryption_key: BigInteger = BigInteger(encryption_key)
        self.signature: Signature = Signature(**signature)


class Coefficient(SerializableObject):
    def __init__(self, coefficient, signature) -> None:
        self.coefficient: BigInteger = BigInteger(coefficient)
        self.signature: Signature = Signature(**signature)


class Point(SerializableObject):
    def __init__(self, alpha, beta, signature) -> None:
        self.alpha: BigInteger = BigInteger(alpha)
        self.beta: BigInteger = beta
        self.signature: Signature = Signature(**signature)


class ListOfCoefficients(SerializableList):
    def __init__(self, *args) -> None:
        super(ListOfCoefficients, self).__init__()
        for coeff_dict in args:
            self.instances.append(Coefficient(**coeff_dict))


class ListOfSignatures(SerializableList):
    def __init__(self, *args) -> None:
        super(ListOfSignatures, self).__init__()
        for sign_dict in args:
            self.instances.append(Signature(**sign_dict))
