from psifos.crypto.tally.homomorphic.decryption import HomomorphicDecryption
from psifos.crypto.tally.mixnet.decryption import MixnetDecryption


class DecryptionFactory():
    @staticmethod
    def create(**kwargs):
        tally_type = kwargs.get("tally_type")
        if tally_type == "homomorphic":
            return HomomorphicDecryption(**kwargs)
        elif tally_type == "mixnet":
            return MixnetDecryption(**kwargs)
        else:
            return None