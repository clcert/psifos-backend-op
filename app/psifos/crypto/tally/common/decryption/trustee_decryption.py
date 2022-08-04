from app.psifos.crypto.tally.common.decryption.decryption_factory import DecryptionFactory
from app.database.serialization import SerializableList


class TrusteeDecryptions(SerializableList):
    def __init__(self, *args) -> None:
        super(TrusteeDecryptions, self).__init__()
        for decryption_dict in args:
            self.instances.append(DecryptionFactory.create(**decryption_dict))
    
    def verify(self, encrypted_tally):
        tallies = encrypted_tally.get_tallies()
        for tally, decryption in zip(tallies, self.instances):
            question_verify = decryption.verify(tally)
            if not question_verify:
                return False
        return True