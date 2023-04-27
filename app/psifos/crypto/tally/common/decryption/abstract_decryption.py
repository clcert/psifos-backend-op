from app.database.serialization import SerializableObject


class AbstractDecryption(SerializableObject):
    """
    Holds the common behaviour of a Trustee's partial decryption
    for a question with an arbitrary tally_type.
    """
    def __init__(self, tally_type) -> None:
        self.tally_type = tally_type

    def verify(self, public_key, a_tally):
        """
        Verifies a tally.
        TODO: Add general verification        
        """
        return True
