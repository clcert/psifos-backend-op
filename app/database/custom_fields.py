import sqlalchemy.types as types
from app.psifos.crypto.elgamal import PublicKey, ListOfCipherTexts
from app.psifos.crypto.sharedpoint import (
    Certificate,
    ListOfCoefficients,
    ListOfSignatures,
    Point,
)
from app.psifos.crypto.tally.common.decryption.trustee_decryption import (
    TrusteeDecryptionsManager,
)
from app.psifos.crypto.tally.common.encrypted_vote import EncryptedVote
from sqlalchemy.dialects.mysql import LONGTEXT
from app.psifos.crypto.tally.mixnet.decryption import ListOfDecryptionFactors, ListOfDecryptionProofs
from app.psifos.crypto.elgamal import ListOfIntegers, ListOfZKProofs


class SerializableField(types.TypeDecorator):
    impl = LONGTEXT
    cache_ok = False
    class_type = None

    def process_bind_param(self, value, dialect):
        if value is None:
            return ""

        return self.class_type.serialize(value)

    def process_result_value(self, value, dialect):
        if value == "" or value is None:
            return None

        return self.class_type.deserialize(value)

# --- Custom SerializableFields ---
class PublicKeyField(SerializableField):
    class_type = PublicKey

class TrusteeDecryptionsField(SerializableField):
    class_type = TrusteeDecryptionsManager


class EncryptedVoteField(SerializableField):
    class_type = EncryptedVote


class CertificateField(SerializableField):
    class_type = Certificate


class CoefficientsField(SerializableField):
    class_type = ListOfCoefficients


class AcknowledgementsField(SerializableField):
    class_type = ListOfSignatures

class PointField(SerializableField):
    class_type = Point

class ListOfCipherTextsField(SerializableField):
    class_type = ListOfCipherTexts

class ListOfIntegersField(SerializableField):
    class_type = ListOfIntegers

class ListOfZKProofsField(SerializableField):
    class_type = ListOfZKProofs

class ListOfDecryptionFactorsField(SerializableField):
    class_type = ListOfDecryptionFactors

class ListOfDecryptionProofsField(SerializableField):
    class_type = ListOfDecryptionProofs