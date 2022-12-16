"""
Mixnet tally for psifos questions.

27-05-2022
"""

from ..common.abstract_tally import AbstractTally
from app.psifos.crypto.elgamal import Ciphertext, ListOfCipherTexts


import requests
import random
import time
from app.config import APP_MIXNET_PREFIX, APP_MIXNET_PORT, APP_MIXNET_TOKEN, MIXNET_NUM_SERVERS, MIXNET_WAIT_INTERVAL
from app.database.serialization import SerializableList

class ListOfEncryptedTexts(SerializableList):
    def __init__(self, *args) -> None:
        super(ListOfEncryptedTexts, self).__init__()
        for ctxts_list in args:
            self.instances.append(ListOfCipherTexts(*ctxts_list))
    

class MixnetTally(AbstractTally):
    """
    Mixnet tally implementation for open questions.
    """
    def __init__(self, tally=None, **kwargs) -> None:
        super(MixnetTally, self).__init__(**kwargs)
        self.tally = ListOfEncryptedTexts(*tally) if self.computed else []

    def compute(self, encrypted_answers, **kwargs) -> None:
        # first we create the list of ciphertexts
        ciphertexts = []
        for enc_ans in encrypted_answers:
            ciphertexts.append([
                Ciphertext.serialize(ctxt, to_json=False)
                for ctxt in enc_ans.get_choices()
            ])
        
        # then we create the payload and send it to each mixnet sv
        for i in range(1, MIXNET_NUM_SERVERS + 1):
            PAYLOAD = {
                "servers_data": [
                    {
                        "name": f"{APP_MIXNET_PREFIX}{j}",
                        "url": f"http://{APP_MIXNET_PREFIX}{j}:{APP_MIXNET_PORT}"
                    }
                    for j in range(1, MIXNET_NUM_SERVERS + 1) if i != j
                ],
                "token": APP_MIXNET_TOKEN, 
                "ciphertexts": ciphertexts
            }
            requests.post(
                url=f"http://{APP_MIXNET_PREFIX}{i}:{APP_MIXNET_PORT}/init",
                params=PAYLOAD
            )
                            
        # once each mixnet sv has been initialized, 
        # we retrieve the encrypted texts if available
        sv_idx = random.randint(1, MIXNET_NUM_SERVERS)
        while True:
            r = requests.get(f"http://{APP_MIXNET_PREFIX}{sv_idx}:{APP_MIXNET_PORT}/get-ciphertexts").json()
            if r["status"] == "COMPUTED_CIPHERTEXTS":
                self.tally = ListOfEncryptedTexts(*r["ciphertexts"])
                break
            time.sleep(MIXNET_WAIT_INTERVAL)

        self.computed = True
        self.num_tallied = len(ciphertexts)
                  

    def decrypt() -> None:
        pass