from app.psifos.crypto.tally.homomorphic.decryption import HomomorphicDecryption
from app.psifos.crypto.tally.mixnet.decryption import MixnetDecryption


class DecryptionFactory():
    @staticmethod
    def create(**kwargs):
        tally_types_and_decrypts = {
            "homomorphic": HomomorphicDecryption,
            "mixnet": MixnetDecryption,
            "stvnc": MixnetDecryption,
        }
        tally_type = kwargs.get("tally_type")
        if tally_type in tally_types_and_decrypts.keys():
            return tally_types_and_decrypts[tally_type](**kwargs)
        return None
