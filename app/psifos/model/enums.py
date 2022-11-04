"""
Enums for Psifos model.

25-04-2022
"""

import enum

class ElectionTypeEnum(str, enum.Enum):
    query = "Query"
    election = "Election"

class ElectionStatusEnum(str, enum.Enum):
    setting_up = "Setting up"
    started = "Started"
    ended = "Ended"
    tally_computed = "Tally computed"
    decryptions_uploaded = "Decryptions uploaded"
    decryptions_combined = "Decryptions combined"
    results_released = "Results released"

class ElectionEventEnum(str, enum.Enum):
    VOTER_FILE_UPLOADED = "voter_file_uploaded"
    ELECTORAL_ROLL_MODIFIED = "electoral_roll_modified"
    TRUSTEE_CREATED = "trustee_created"
    PUBLIC_KEY_GENERATED = "public_key_generated"
    VOTING_STARTED = "voting_started"
    VOTING_STOPPED = "voting_stopped"
    TALLY_COMPUTED = "tally_computed"
    TRUSTEE_DECRYPTION_RECIEVED = "trustee_decryption_recieved"
    DECRYPTIONS_COMBINED = "decryptions_combined"