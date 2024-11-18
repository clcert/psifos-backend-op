from app.psifos.crypto.tally.common.decryption.decryption_factory import (
    DecryptionFactory,
)
from app.database.serialization import SerializableList, SerializableObject


class TrusteeDecryptions(SerializableList):
    def __init__(self, *args) -> None:
        super(TrusteeDecryptions, self).__init__()
        for decryption_dict in args:
            self.instances.append(DecryptionFactory.create(**decryption_dict))

    def verify(self, public_key, encrypted_tally):
        for tally, decryption in zip(encrypted_tally, self.instances):
            question_verify = decryption.verify(public_key, tally)
            if not question_verify:
                return False
        return True


class TrusteeDecryptionsGroup(SerializableObject):
    def __init__(self, group, decryptions) -> None:
        super(TrusteeDecryptionsGroup, self).__init__()
        self.group = group
        self.decryptions = TrusteeDecryptions(*decryptions)


class TrusteeDecryptionsManager(SerializableList):
    def __init__(self, *args) -> None:
        super(TrusteeDecryptionsManager, self).__init__()
        for decryptions_dict in args:
            self.instances.append(decryptions_dict)
