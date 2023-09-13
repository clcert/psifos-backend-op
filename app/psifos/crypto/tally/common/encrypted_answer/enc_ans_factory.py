from app.psifos.crypto.tally.homomorphic.encrypted_answer import EncryptedClosedAnswer
from app.psifos.crypto.tally.mixnet.encrypted_answer import EncryptedOpenAnswer, EncryptedMixnetAnswer, EncryptedStvncAnswer
from app.database.serialization import SerializableObject


class EncryptedAnswerFactory(SerializableObject):
    def create(**kwargs):
        enc_ans_types = {
            "encrypted_closed_answer": EncryptedClosedAnswer,
            "encrypted_open_answer": EncryptedOpenAnswer,
            "encrypted_mixnet_answer": EncryptedMixnetAnswer,
            "encrypted_stvnc_answer": EncryptedStvncAnswer,
        }
        q_type = kwargs.get("enc_ans_type", None)
        if q_type in enc_ans_types.keys():
            return enc_ans_types[q_type](**kwargs)
        return None