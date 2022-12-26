"""
Mixnet tally for psifos questions.

27-05-2022
"""

from ..common.abstract_tally import AbstractTally
from app.psifos.crypto.elgamal import Ciphertext, ListOfCipherTexts


import requests
import random
import time
from app.config import MIXNET_01_NAME, MIXNET_01_URL, MIXNET_02_NAME, MIXNET_02_URL, MIXNET_03_NAME, MIXNET_03_URL, MIXNET_TOKEN, MIXNET_WIDTH, MIXNET_WAIT_INTERVAL
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
        
        server_names = [MIXNET_01_NAME, MIXNET_02_NAME, MIXNET_03_NAME]
        server_urls = [MIXNET_01_URL, MIXNET_02_URL, MIXNET_03_URL]

        # then we create the payload and send it to each mixnet sv
        for name, url in zip(server_names, server_urls):
            PAYLOAD = {
                "servers_data": [
                    {
                        "name": a_name,
                        "url": a_url
                    }
                    for a_name, a_url in zip(server_names, server_urls) if name != a_name and url != a_url 
                ],
                "token": MIXNET_TOKEN, 
                "ciphertexts": ciphertexts
            }
            requests.post(url=f"{url}/init", json=PAYLOAD)
        
        # once each mixnet sv has been initialized, 
        # we retrieve the encrypted texts if available
        sv_idx = random.randint(0, len(server_urls)-1)
        print(f"\n\nMIXSERVER{sv_idx+1} SELECCIONADO!\n\n")
        while True:
            r = requests.get(f"{server_urls[sv_idx]}/get-ciphertexts").json()
            if r["status"] == "CIPHERTEXTS_COMPUTED":
                response_content = [mixnet_output["ciphertexts"] for mixnet_output in r["content"]]
                self.tally = ListOfEncryptedTexts(*response_content)
                break
            time.sleep(MIXNET_WAIT_INTERVAL)

        self.computed = True
        self.num_tallied = len(ciphertexts)
                  

    def decrypt() -> None:
        pass