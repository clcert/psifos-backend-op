"""
Mixnet tally for close massive psifos questions.

14-09-2023
"""

from app.psifos.crypto.tally.mixnet.tally import MixnetTally

class CloseMassiveTally(MixnetTally):
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