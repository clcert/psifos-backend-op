"""
common workflows and algorithms for Psifos tallies.

Ben Adida
reworked for Psifos: 27-05-2022
"""
import itertools

from psifos.crypto.elgamal import ListOfCipherTexts
from ..common.abstract_tally import AbstractTally
from ..common.dlogtable import DLogTable

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
            self.tally = [0] * self.question.total_options

        else:
            self.tally = ListOfCipherTexts(*tally)
    
    def compute(self, encrypted_answers, weights):
        self.computed = True
        for enc_ans, weight in zip(encrypted_answers, weights):
            choices = enc_ans.get_choices()
            for answer_num in range(len(self.tally)):
                # do the homomorphic addition into the tally
                choices[answer_num].pk = self.public_key
                choices[answer_num].alpha = pow(choices[answer_num].alpha, weight, self.public_key.p)
                choices[answer_num].beta = pow(choices[answer_num].beta, weight, self.public_key.p)
                self.tally[answer_num] = choices[answer_num] * self.tally[answer_num]
            self.num_tallied += 1
        a_tally = ListOfCipherTexts()
        a_tally.set_instances(self.tally)
        self.tally = a_tally

    ####
    def decryption_factors_and_proofs(self, sk):
        """
        returns an array of decryption factors and a corresponding array of decryption proofs.
        makes the decryption factors into strings, for general Helios / JS compatibility.
        """
        # for all choices of all questions (double list comprehension)
        question_factors = []
        question_proofs = []

        for answer_num in range(len(self.tally)):
            # do decryption and proof of it
            dec_factor, proof = sk.decryption_factor_and_proof(self.tally[answer_num])

            # look up appropriate discrete log
            # this is the string conversion
            question_factors.append(dec_factor)
            question_proofs.append(proof)

        return question_factors, question_proofs

    def decrypt(self, decryption_factors, t, max_weight=1):
        """
        decrypt a tally given decryption factors

        The decryption factors are a list of decryption factor sets, for each trustee.
        Each decryption factor set is a list of lists of decryption factors (questions/answers).
        """

        # pre-compute a dlog table
        dlog_table = DLogTable(base=self.public_key.g, modulus=self.public_key.p)
        dlog_table.precompute(self.num_tallied * max_weight)

        q_result = []

        for a_num, a in enumerate(self.tally.instances):
            last_raw_value = None
            
            # generate al subsets of size t+1 and compare values between each iteration
            iterator = itertools.combinations([
                (di, df[a_num]) 
                for di, df in decryption_factors
            ], t+1)
            
            for subset_factor_list in iterator:
                raw_value = a.decrypt(subset_factor_list, self.public_key)
                
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
