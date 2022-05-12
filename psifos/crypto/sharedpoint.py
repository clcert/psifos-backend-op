"""
SharedPoint classes for Psifos.

14-04-2022
"""

from psifos.serialization import SerializableObject
import json


class Signature(SerializableObject):
    def __init__(self, challenge, response) -> None:
        self.challenge: int = int(challenge)
        self.response: int = int(response)


class SerializableSPObject(SerializableObject):
    @classmethod
    def serialize(cls, obj) -> str:
        if obj is None:
            return '{}'

        if isinstance(obj, str):
            return obj

        obj.signature = Signature.serialize(obj=obj)
        return json.dumps(obj.__dict__)

    @classmethod
    def deserialize(cls, json_data: str) -> str:
        data = json.loads(json_data)
        data["signature"] = Signature.deserialize(data["signature"])
        return cls(**data)


class Certificate(SerializableSPObject):
    def __init__(self, signature_key, encryption_key, signature) -> None:
        self.signature_key: int = int(signature_key)
        self.encryption_key: int = int(encryption_key)
        self.signature: Signature = signature


class Coefficient(SerializableSPObject):
    def __init__(self, coefficient, signature) -> None:
        self.coeficcient: int = int(coefficient)
        self.signature: Signature = signature


class Point(SerializableSPObject):
    def __init__(self, alpha, signature) -> None:
        self.alpha: int = int(alpha)
        self.signature: Signature = signature
