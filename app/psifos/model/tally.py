import requests
import random
import time
import re
import itertools
import enum
import json

from sqlalchemy import Column, Text, Integer, Boolean, JSON, Enum, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base

from app.psifos.crypto.tally.mixnet.tally import MixnetTally
from app.psifos.crypto.tally.mixnet.utils import is_blank_ballot, is_null_ballot, is_invalid_ballot
from app.psifos.crypto.tally.mixnet.utils import parseRoundResumes, parseTalliesResumes
from psifospoll import STVElection

from app.psifos.crypto.tally.common.abstract_tally import AbstractTally
from app.psifos.crypto.tally.common.dlogtable import DLogTable
from app.database.custom_fields import ListOfCipherTextsField

from app.psifos.crypto.elgamal import Ciphertext, ListOfCipherTexts

from app.config import MIXNET_01_NAME, MIXNET_01_URL, MIXNET_02_NAME, MIXNET_02_URL, MIXNET_03_NAME, MIXNET_03_URL, MIXNET_TOKEN, MIXNET_WIDTH, MIXNET_WAIT_INTERVAL
from app.database.serialization import SerializableList


class TallyTypeEnum(str, enum.Enum):
    HOMOMORPHIC = "HOMOMORPHIC"
    MIXNET = "MIXNET"
    STVNC = "STVNC"

class Tally(Base):
    __tablename__ = "psifos_tallies"

    id = Column(Integer, primary_key=True, index=True)
    election_id = Column(Integer, ForeignKey("psifos_election.id"), nullable=False)
    group = Column(Text, nullable=False)
    with_votes = Column(Boolean, default=False)
    tally_type = Column(Enum(TallyTypeEnum), nullable=False)
    q_num = Column(Integer, nullable=False)
    num_options = Column(Integer, nullable=False, default=0)
    computed = Column(Boolean, default=False)
    num_tallied = Column(Integer, nullable=False, default=0)
    max_answers = Column(Integer, nullable=True)
    num_of_winners = Column(Integer, nullable=True)
    include_blank_null = Column(Boolean, nullable=True)
    tally = Column(Text, nullable=False, default=[])

    election = relationship("Election", back_populates="encrypted_tally")

    def __repr__(self):
        return f"Tally(id={self.id}, tally_type={self.tally_type}, election_id={self.election_id}, group={self.group}, with_votes={self.with_votes})"
    
    __mapper_args__ = {
        'polymorphic_on': tally_type,
        'polymorphic_identity': 'tally',
        'with_polymorphic': '*'
    }

class HomomorphicTally(Tally):
    """
    Homomorhic tally implementation for closed questions.
    """

    __mapper_args__ = {
        'polymorphic_identity': TallyTypeEnum.HOMOMORPHIC,
    }

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
        return ListOfCipherTexts(*json.loads(self.tally))
    
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
        self.tally = a_tally.serialize(s_list=a_tally, to_json=True)

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
        for a_num, a_ctxt in enumerate(tally.instances):
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

        result = [dlog_table.lookup(result) for result in q_result]

        return result
    
class ListOfEncryptedTexts(SerializableList):
    def __init__(self, *args) -> None:
        super(ListOfEncryptedTexts, self).__init__()
        for ctxts_list in args:
            self.instances.append(ListOfCipherTexts(*ctxts_list))


def get_key_params_for_mixnet(public_key):
    p_hex = hex(public_key.p)[2:]
    g_hex = hex(public_key.g)[2:]
    q_hex = hex(public_key.q)[2:]
    return p_hex + " " + g_hex + " " + q_hex


class MixnetTally(Tally):
    """
    Mixnet tally implementation for open questions.
    """
    __mapper_args__ = {
        'polymorphic_identity': TallyTypeEnum.MIXNET,
    }


    def __init__(self, tally=None, **kwargs) -> None:
        super(MixnetTally, self).__init__(**kwargs)
        self.tally = ListOfEncryptedTexts(*tally) if self.computed else []
        self.tally_type = "mixnet"

    def get_tally(self):
        return ListOfEncryptedTexts(*json.loads(self.tally))
        
    def compute(self, public_key, encrypted_answers, **kwargs) -> None:        
        # first we create the list of ciphertexts
        ciphertexts = []
        for enc_ans in encrypted_answers:
            ciphertexts.append([
                Ciphertext.serialize(ctxt, to_json=False)
                for ctxt in enc_ans.get_choices()
            ])
        election = kwargs.get("election")
        election_name = election.short_name
        election_uuid = election.uuid

        mixnet_width = kwargs.get("width")
        server_names = [MIXNET_01_NAME, MIXNET_02_NAME, MIXNET_03_NAME]
        server_urls = [MIXNET_01_URL, MIXNET_02_URL, MIXNET_03_URL]

        TOKEN = re.sub(r'[^a-zA-Z0-9]+', '', f'{election_name}{election_uuid}{time.time()}{self.q_num}')

        for name, url in zip(server_names, server_urls):
            requests.post(url=f"{url}/configure-mixnet", json={
                'mixnet_width': mixnet_width,
                'mixnet_num_servers': str(len(server_names)),
                'key_params': get_key_params_for_mixnet(public_key),
                'token' : TOKEN
            })

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
                "public_key_g": public_key.g,
                "public_key_p": public_key.p,
                "public_key_q": public_key.q,
                "public_key_y": public_key.y,
                "token": TOKEN, 
                "ciphertexts": ciphertexts
            }
            requests.post(url=f"{url}/init", json=PAYLOAD)
        
        # once each mixnet sv has been initialized, 
        # we retrieve the encrypted texts if available
        sv_idx = random.randint(0, len(server_urls)-1)
        while True:
            r = requests.get(f"{server_urls[sv_idx]}/get-ciphertexts?token={TOKEN}").json()
            if r["status"] == "CIPHERTEXTS_COMPUTED":
                response_content = [mixnet_output["ciphertexts"] for mixnet_output in r["content"]]
                tally_result = ListOfEncryptedTexts(*response_content)
                self.tally = tally_result.serialize(s_list=tally_result, to_json=True)
                break
            time.sleep(MIXNET_WAIT_INTERVAL)

        self.computed = True
        self.num_tallied = len(ciphertexts)
                  

    def decrypt(self, public_key, decryption_factors, t, **kwargs) -> None:
        q_result = []
        tally = self.get_tally()
        for vote_num, vote_ctxts in enumerate(tally.instances):
            v_result = []
            for ctxt_num, ctxt in enumerate(vote_ctxts.instances):
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
        return count_vote
    
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
                q_result[null_vote - 2] += 1

            # check blank vote
            elif len(set_vote) == 1 and blank_vote in set_vote:
                q_result[blank_vote - 2] += 1

            # count normal counts
            else:   
                for answer in vote:
                    q_result[answer - 1] += 1 if answer != blank_vote else 0

        return q_result

class STVTally(MixnetTally):

    __mapper_args__ = {
        'polymorphic_identity': TallyTypeEnum.STVNC,
    }

    def __init__(self, tally=None, **kwargs) -> None:
        MixnetTally.__init__(self, tally, **kwargs)
        self.tally_type = "stvnc"
        self.num_of_winners = int(kwargs["num_of_winners"])
        self.include_blank_null = kwargs["include_blank_null"]
        self.max_answers = int(kwargs["max_answers"])
        
    def stv(
        self, blank_count, null_count, ballot_list, candidates_list,
    ):
        result = {
            "roundresumes": {},
            "talliesresumes": {},
            "winnerslist": [],
            "quota": None,
            "blankvotes": blank_count,
            "nullvotes": null_count,
        }
        
        if len(ballot_list) > 0:
            election = STVElection()
            election.runElection(self.num_of_winners, candidates_list, ballot_list)
            result["roundresumes"] = election.getRoundResumes()
            result["talliesresumes"] = election.getTalliesResumes()
            result["winnerslist"] = election.getWinnersList()
            result["quota"] = election.getQuota()

        return result

    def count_votes(self, votes, total_closed_options):
        # All ballots have the same length
        num_of_formal_options = total_closed_options - 2 if self.include_blank_null else total_closed_options
        candidates_list = list(range(num_of_formal_options))

        blank_count = 0
        null_count = 0
        ballot_list = []
        for ballot in votes:
            is_blank = is_blank_ballot(ballot, total_closed_options, self.max_answers)
            is_null = is_null_ballot(ballot, total_closed_options, self.max_answers)
            is_invalid = is_invalid_ballot(
                ballot, total_closed_options, num_of_formal_options, self.max_answers
            )
            if self.include_blank_null and is_blank:
                blank_count += 1
            elif is_null or is_invalid or (
                not self.include_blank_null and is_blank
            ):
                null_count += 1
            else:
                ballot_list.append(list(filter(
                    lambda candidate: candidate in candidates_list,
                    ballot)
                ))

        # Calculates the stv result
        result = self.stv(
            blank_count, null_count, ballot_list, candidates_list
        )

        return str(result)
