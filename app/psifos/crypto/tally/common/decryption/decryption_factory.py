class DecryptionFactory():
    @staticmethod
    def create(**kwargs):
        from app.psifos.model.decryptions import HomomorphicDecryption, MixnetDecryption
        tally_types_and_decrypts = {
            "homomorphic": HomomorphicDecryption,
            "mixnet": MixnetDecryption,
            "stvnc": MixnetDecryption,
        }
        tally_type = kwargs.get("tally_type")
        kwargs["decryption_type"] = tally_type.upper()
        del kwargs["tally_type"]
        if tally_type in tally_types_and_decrypts.keys():
            return tally_types_and_decrypts[tally_type](**kwargs)
        return None
