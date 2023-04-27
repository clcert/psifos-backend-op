"""
Mixnet tally for psifos questions.

27-05-2022
"""

import itertools
from ..common.abstract_tally import AbstractTally
from app.psifos.crypto.elgamal import Ciphertext, ListOfCipherTexts


import requests
import random
import time
import re
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

    def get_tally(self):
        return [x.instances for x in self.tally.instances]
        
    def compute(self, public_key, encrypted_answers, **kwargs) -> None:
        # first we create the list of ciphertexts
        ciphertexts = []
        for enc_ans in encrypted_answers:
            ciphertexts.append([
                Ciphertext.serialize(ctxt, to_json=False)
                for ctxt in enc_ans.get_choices()
            ])
        
        election = kwargs.get("election")
        election_name = election.election_name
        election_uuid = election.election_uuid
        
        server_names = [MIXNET_01_NAME, MIXNET_02_NAME, MIXNET_03_NAME]
        server_urls = [MIXNET_01_URL, MIXNET_02_URL, MIXNET_03_URL]

        TOKEN = re.sub(r'[^a-zA-Z0-9]+', '', f'{election_name}{election_uuid}')

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
                "public_key_y": public_key.y,
                "token": TOKEN, 
                "ciphertexts": ciphertexts
            }
            print(f"\n{PAYLOAD}\n")
            requests.post(url=f"{url}/init", json=PAYLOAD)
        
        # once each mixnet sv has been initialized, 
        # we retrieve the encrypted texts if available
        sv_idx = random.randint(0, len(server_urls)-1)
        print(f"\n\nMIXSERVER{sv_idx+1} SELECCIONADO!\n\n")
        while True:
            r = requests.get(f"{server_urls[sv_idx]}/get-ciphertexts?token={TOKEN}").json()
            if r["status"] == "CIPHERTEXTS_COMPUTED":
                response_content = [mixnet_output["ciphertexts"] for mixnet_output in r["content"]]
                self.tally = ListOfEncryptedTexts(*response_content)
                break
            time.sleep(MIXNET_WAIT_INTERVAL)

        self.computed = True
        self.num_tallied = len(ciphertexts)
                  

    def decrypt(self, public_key, decryption_factors, t, **kwargs) -> None:
        q_result = []
        tally = self.get_tally()
        for vote_num, vote_ctxts in enumerate(tally):
            v_result = []
            for ctxt_num, ctxt in enumerate(vote_ctxts):
                last_raw_value = None
                
                # generate al subsets of size t+1 and compare values between each iteration
                iterator = itertools.combinations([
                    (di, df[vote_num][ctxt_num]) 
                    for di, df in decryption_factors
                ], t+1)
                
                for subset_factor_list in iterator:
                    raw_value = ctxt.decrypt(
                        decryption_factors=subset_factor_list,
                        public_key=public_key,
                        decode_m=True
                    )
                    
                    if raw_value is None:
                        raise Exception("Error computing decryption: None returned")
                    if last_raw_value is not None and raw_value != last_raw_value:
                        raise Exception("Not all decryptions agree!")
                    last_raw_value = raw_value
                v_result.append(raw_value)
            q_result.append(v_result)

        count_vote = self.count_votes(q_result, self.num_options)
        result = {
            "tally_type": "mixnet",
            "ans_results": count_vote
        }

        return result

    def count_votes(self, votes, total_closed_options):

        # The votes come with a +1 from the front, take it into account when counting
        q_result = [0] * total_closed_options
        null_vote = total_closed_options + 1
        blank_vote = null_vote - 1

        # Lets count by votes
        for vote in votes:
            set_vote = set(vote)

            # check null vote
            if null_vote in vote:
                q_result[null_vote - 1] += 1

            # check blank vote
            elif len(set_vote) == 1 and blank_vote in set_vote:
                q_result[blank_vote - 1] += 1

            # count normal counts
            else:   
                for answer in vote:
                    q_result[answer - 1] += 1 if answer != blank_vote else 0

        return q_result