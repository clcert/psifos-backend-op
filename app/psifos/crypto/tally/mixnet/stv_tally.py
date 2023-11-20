"""
Mixnet tally for STV psifos questions.

16-11-2023
"""

from app.psifos.crypto.tally.mixnet.tally import MixnetTally
from stvpoll.scottish_stv import ScottishSTV

class STVTally(MixnetTally):
    def count_votes(self, votes, total_closed_options):
        # All ballots have the same length
        formal_options = len(votes[0])
        null_index = formal_options + 1
        blank_index = formal_options
        null_id = total_closed_options + 1
        blank_id = total_closed_options
        null_vote = [null_id]*formal_options
        blank_vote = [blank_id]*formal_options
        
        # Some aux functions
        def is_blank_vote(vote):
            return vote == blank_vote
        def is_null_vote(vote):
            return vote == null_vote
        def is_invalid_vote(vote):
            for el in vote:
                closed_options = list(range(formal_options)) + [null_id, blank_id]
                isValid = el in closed_options
                if vote.count(el) > 1 or not isValid:
                    return True
            return False

        # Analyzes each vote
        poll = ScottishSTV(seats=1, candidates=list(range(formal_options)))
        blank_count = 0
        null_count = 0
        for vote in votes:
            if is_blank_vote(vote):
                blank_count += 1
            elif is_null_vote(vote) or is_invalid_vote(vote):
                null_count += 1
            else:
                candidates = list(range(formal_options))
                final_vote = []
                for candidate in vote:
                    if candidate in candidates:
                        final_vote += [candidate]
                    else:
                        break

                ## lo agrego al calculo de stv
                poll.add_ballot(final_vote, 1)

        # Calculates the stv result
        stv_result = list(poll.calculate())

        # Forms the final result 
        results = [0] * total_closed_options
        for winner_id in stv_result:
            results[winner_id] = 1
        if total_closed_options != formal_options:
            results[null_index] = null_count
            results[blank_index] = blank_count

        return results
