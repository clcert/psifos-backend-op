"""
common workflows and algorithms for Psifos tallies.

Ben Adida
reworked for Psifos: 27-05-2022
"""
import itertools

from app.psifos.crypto.elgamal import ListOfCipherTexts
from app.psifos.crypto.tally.common.abstract_tally import AbstractTally
from app.psifos.crypto.tally.common.dlogtable import DLogTable

class HomomorphicTally(AbstractTally):
    """
    Homomorhic tally implementation for closed questions.
    """
    def __init__(self, tally=None, **kwargs) -> None:
        """
        HomomorphicTally constructor, allows the creation of this tally.
        
        If computed==False then questions cannot be None.
        Else, tally cannot be None
        """
        super(HomomorphicTally, self).__init__(**kwargs)
        
        if not self.computed:
            self.tally = [0] * self.num_options

        else:
            self.tally = ListOfCipherTexts(*tally)
    
    def get_tally(self):
        return self.tally.instances
    
    def compute(self, public_key, encrypted_answers, weights, **kwargs):
        self.computed = True
        for enc_ans, weight in zip(encrypted_answers, weights):
            choices = enc_ans.get_choices()
            for answer_num in range(len(self.tally)):
                # do the homomorphic addition into the tally
                choices[answer_num]._pk = public_key
                choices[answer_num].alpha = pow(choices[answer_num].alpha, weight, public_key.p)
                choices[answer_num].beta = pow(choices[answer_num].beta, weight, public_key.p)
                self.tally[answer_num] = choices[answer_num] * self.tally[answer_num]
            self.num_tallied += 1
        a_tally = ListOfCipherTexts()
        a_tally.set_instances(self.tally)
        self.tally = a_tally

    def decrypt(self, public_key, decryption_factors, t, max_weight=1, **kwargs):
        """
        decrypt a tally given decryption factors

        The decryption factors are a list of decryption factor sets, for each trustee.
        Each decryption factor set is a list of lists of decryption factors (questions/answers).
        """

        # pre-compute a dlog table
        dlog_table = DLogTable(base=public_key.g, modulus=public_key.p)
        dlog_table.precompute(self.num_tallied * max_weight)

        q_result = []

        tally = self.get_tally()
        for a_num, a_ctxt in enumerate(tally):
            last_raw_value = None
            
            # generate al subsets of size t+1 and compare values between each iteration
            iterator = itertools.combinations([
                (di, df[a_num]) 
                for di, df in decryption_factors
            ], t+1)
            
            for subset_factor_list in iterator:
                raw_value = a_ctxt.decrypt(
                    decryption_factors=subset_factor_list, 
                    public_key=public_key
                )
                
                if raw_value is None:
                    raise Exception("Error computing decryption: None returned")
                if last_raw_value is not None and raw_value != last_raw_value:
                    raise Exception("Not all decryptions agree!")
                last_raw_value = raw_value
            q_result.append(raw_value)

        result = {
            "tally_type": "homomorphic",
            "ans_results": [dlog_table.lookup(result) for result in q_result]
        }

        return result
