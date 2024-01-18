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

    def count_votes(self, votes, total_closed_options):
        # All ballots have the same length
        total_formal_options = len(votes[0])
        includes_informal_options = total_formal_options != total_closed_options
        candidates_list = list(range(total_formal_options))

        blank_count = 0
        null_count = 0
        ballot_list = []
        for ballot in votes:
            is_blank = is_blank_ballot(ballot, total_closed_options)
            is_null = is_null_ballot(ballot, total_closed_options)
            is_invalid = is_invalid_ballot(
                ballot, total_closed_options, total_formal_options
            )
            if includes_informal_options and is_blank:
                blank_count += 1
            elif is_null or is_invalid or (
                not includes_informal_options and is_blank
            ):
                null_count += 1
            else:
                ballot_list.append(list(filter(
                    lambda candidate: candidate in candidates_list,
                    ballot)
                ))

        # Calculates the stv result
        seats = self.num_of_winners
        election = STVElection()
        election.runElection(seats, candidates_list, ballot_list)
        stv_results = [
            parseRoundResumes(election.getRoundResumes()),
            parseTalliesResumes(election.getTalliesResumes()),
            election.getWinnersList(),
        ]
        
        results = [
            stv_results,
            [blank_count, null_count]
        ]

        return results
