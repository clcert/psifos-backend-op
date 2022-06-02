"""
Crypto Utils
"""
import base64
import math

from Crypto.Hash import SHA256
from Crypto.Random.random import StrongRandom
from Crypto.Util.number import inverse

from psifos.serialization import SerializableObject


class BigInteger(SerializableObject):
    """
    Abstraction layer for handling big integers.
    """

    def __init__(self, value) -> None:
        self.value = int(value)

    @classmethod
    def serialize(cls, obj, **kwargs) -> str:
        return str(obj.value)

    @classmethod
    def deserialize(cls, json_data) -> int:
        return int(json_data)
    
    def __mul__(self, other):
        if isinstance(other, int):
            return BigInteger(self.value * other)
        elif isinstance(other, BigInteger):
            return BigInteger(self.value * other.value)
    
    def __rmul__(self, other):
        if isinstance(other, int):
            return BigInteger(self.value * other)



random = StrongRandom()


def random_mpz_lt(maximum, strong_random=random):
    n_bits = int(math.floor(math.log(maximum, 2)))
    res = strong_random.getrandbits(n_bits)
    while res >= maximum:
        res = strong_random.getrandbits(n_bits)
    return res


random.mpz_lt = random_mpz_lt


def hash_b64(s):
    """
    hash the string using sha256 and produce a base64 output
    removes the trailing "="
    """
    hasher = SHA256.new(s.encode('utf-8'))
    result = base64.b64encode(hasher.digest())[:-1].decode('ascii')
    return result
