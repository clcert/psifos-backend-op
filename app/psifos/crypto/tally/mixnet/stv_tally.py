"""
Mixnet tally for STV psifos questions.

18-01-2024
"""

from app.psifos.crypto.tally.mixnet.tally import MixnetTally
from app.psifos.crypto.tally.mixnet.utils import is_blank_ballot, is_null_ballot, is_invalid_ballot
from app.psifos.crypto.tally.mixnet.utils import parseRoundResumes, parseTalliesResumes
from psifospoll import STVElection

class STVTally(MixnetTally):
    def __init__(self, tally=None, **kwargs) -> None:
        MixnetTally.__init__(self, tally, **kwargs)
        self.tally_type = "stvnc"
        self.num_of_winners = int(kwargs["num_of_winners"])
        self.include_blank_null = kwargs["include_blank_null"]
        
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
            is_blank = is_blank_ballot(ballot, total_closed_options)
            is_null = is_null_ballot(ballot, total_closed_options)
            is_invalid = is_invalid_ballot(
                ballot, total_closed_options, num_of_formal_options
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
