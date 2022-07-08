from psifos.crypto.tally.homomorphic.encrypted_answer import EncryptedClosedAnswer
from psifos.crypto.tally.mixnet.encrypted_answer import EncryptedOpenAnswer
from psifos.serialization import SerializableObject


class EncryptedAnswerFactory(SerializableObject):
    def create(**kwargs):
        q_type = kwargs.get("enc_ans_type", None)
        if q_type == "encrypted_closed_answer":
            return EncryptedClosedAnswer(**kwargs)
        elif q_type == "encrypted_open_answer":
            return EncryptedOpenAnswer(**kwargs)
        else:
            return None