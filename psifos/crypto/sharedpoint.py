"""
SharedPoint classes for Psifos.

14-04-2022
"""

from psifos.serialization import SerializableList, SerializableObject


class Signature(SerializableObject):
    def __init__(self, challenge, response) -> None:
        self.challenge: int = int(challenge)
        self.response: int = int(response)


class Certificate(SerializableObject):
    def __init__(self, signature_key, encryption_key, signature) -> None:
        self.signature_key: int = int(signature_key)
        self.encryption_key: int = int(encryption_key)
        self.signature: Signature = signature


class Coefficient(SerializableObject):
    def __init__(self, coefficient, signature) -> None:
        self.coefficient: int = int(coefficient)
        self.signature: Signature = signature


class Point(SerializableObject):
    def __init__(self, alpha, signature) -> None:
        self.alpha: int = int(alpha)
        self.signature: Signature = signature


class ListOfCoefficients(SerializableList):
    def __init__(self, *args) -> None:
        super(ListOfCoefficients, self).__init__()
        for coeff_dict in args:
            self.instances.append(Coefficient(**coeff_dict))


class ListOfSignatures(SerializableList):
    def __init__(self, *args) -> None:
        super(ListOfSignatures, self).__init__()
        for sign_dict in args:
            self.instances.append(Coefficient(**sign_dict))
