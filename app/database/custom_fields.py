import sqlalchemy.types as types
from app.psifos.crypto.elgamal import PublicKey
from app.psifos.crypto.sharedpoint import Certificate, ListOfCoefficients, ListOfSignatures, Point
from app.psifos.crypto.tally.common.decryption.trustee_decryption import TrusteeDecryptionsManager
from app.psifos.crypto.tally.common.encrypted_vote import EncryptedVote
from app.psifos.crypto.tally.tally import TallyManager
from app.psifos.psifos_object.result import ElectionResultManager
from app.psifos.psifos_object.questions import Questions
from sqlalchemy.dialects.mysql import LONGTEXT

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
    cache_ok = False

    
class QuestionsField(SerializableField):
    class_type = Questions
    cache_ok = False

    
class TallyManagerField(SerializableField):
    class_type = TallyManager
    cache_ok = False

    
class TrusteeDecryptionsField(SerializableField):
    class_type = TrusteeDecryptionsManager
    cache_ok = False

    
class ElectionResultField(SerializableField):
    class_type = ElectionResultManager
    cache_ok = False

    
class EncryptedVoteField(SerializableField):
    class_type = EncryptedVote
    cache_ok = False

    
class CertificateField(SerializableField):
    class_type = Certificate
    cache_ok = False

    
class CoefficientsField(SerializableField):
    class_type = ListOfCoefficients
    cache_ok = False


class AcknowledgementsField(SerializableField):
    class_type = ListOfSignatures
    cache_ok = False

class PointField(SerializableField):
    class_type = Point
    cache_ok = False
