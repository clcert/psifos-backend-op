"""
Mixnet tally for STV psifos questions.

14-09-2023
"""

from app.psifos.crypto.tally.mixnet.tally import MixnetTally
from stvpoll.scottish_stv import ScottishSTV

class STVTally(MixnetTally):
    def count_votes(self, votes, total_closed_options):
        # STV questions doesn't include blank and null options
        control_vote = votes[0]
        if (total_closed_options == len(control_vote)):
            poll = ScottishSTV(seats=1, candidates=sorted(votes[0]))

            # Add each vote to the poll
            for vote in votes:
                poll.add_ballot(vote, 1)

            # Calculates the result
            result = list(poll.calculate())
            return result
