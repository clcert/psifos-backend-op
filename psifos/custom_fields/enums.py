"""
Enums for Psifos model.

25-04-2022
"""

import enum

class ElectionTypeEnum(enum.Enum):
    query = "Query"
    election = "Election"

class ElectionStatusEnum(enum.Enum):
    setting_up = "Setting up"
    started = "Started"
    ended = "Ended"
    tally_computed = "Tally computed"
    decryptions_uploaded = "Decryptions uploaded"
    decryptions_combined = "Decryptions combined"
    results_released = "Results released"

