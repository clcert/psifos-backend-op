"""
Mixnet tally for psifos questions.

27-05-2022
"""

from ..common.abstract_tally import AbstractTally
from .encrypted_answer import EncryptedOpenAnswer


import requests
from app.config import APP_MIXNET_URL
from app.database.serialization import SerializableList
class ListOfEncryptedTexts(SerializableList):
    pass

class MixnetTally(AbstractTally):
    """
    Mixnet tally implementation for open questions.
    """
    def __init__(self, tally=None, **kwargs) -> None:
        super(MixnetTally, self).__init__(**kwargs)

        self.tally = ListOfEncryptedTexts(*tally) if self.computed else []

    def compute(self, encrypted_answers, **kwargs) -> None:
        mixnet_enc_ans = [EncryptedOpenAnswer.serialize(obj=enc_ans) for enc_ans in encrypted_answers]
        
        # send enc_ans list to Mixnet
        PARAMS = {"encrypted_answers": mixnet_enc_ans}
        r = requests.post(url=APP_MIXNET_URL, params=PARAMS)
        
        # extracting data in json format
        self.tally = r.json()
        a_tally = ListOfEncryptedTexts()
        a_tally.set_instances(self.tally)
        self.tally = a_tally

        self.computed = True
        self.num_tallied = len(mixnet_enc_ans)
                  

    def decrypt() -> None:
        pass