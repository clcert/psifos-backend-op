from helios.serialization import SerializableObject
class TestObject(SerializableObject):
    def __init__(self, public_key = None, secret_key = None) -> None:
        self.public_key = public_key
        self.secret_key = secret_key