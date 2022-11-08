import sqlalchemy.types as types
from app.psifos.crypto.elgamal import PublicKey
from app.psifos.crypto.sharedpoint import Certificate, ListOfCoefficients, ListOfSignatures, Point
from app.psifos.crypto.tally.common.decryption.trustee_decryption import TrusteeDecryptions
from app.psifos.crypto.tally.common.encrypted_vote import EncryptedVote
from app.psifos.crypto.tally.tally import TallyManager
from app.psifos.psifos_object.result import ElectionResult
from app.psifos.psifos_object.questions import Questions

class SerializableField(types.TypeDecorator):
    impl = types.Text
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

    
class QuestionsField(SerializableField):
    class_type = Questions

    
class TallyManagerField(SerializableField):
    class_type = TallyManager

    
class TrusteeDecryptionsField(SerializableField):
    class_type = TrusteeDecryptions

    
class ElectionResultField(SerializableField):
    class_type = ElectionResult

    
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
