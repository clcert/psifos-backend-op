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
    computing_tally = "Computing Tally"
    tally_computed = "Tally computed"
    decryptions_uploaded = "Decryptions uploaded"
    decryptions_combined = "Decryptions combined"
    results_released = "Results released"


class ElectionEventEnum(str, enum.Enum):
    @classmethod
    def has_member_key(cls, key):
        return key in cls.__members__.values()


class ElectionPublicEventEnum(ElectionEventEnum):
    VOTER_FILE_UPLOADED = "voter_file_uploaded"
    ELECTORAL_ROLL_MODIFIED = "electoral_roll_modified"
    TRUSTEE_CREATED = "trustee_created"
    PUBLIC_KEY_UPLOADED = "public_key_uploaded"
    VOTING_STARTED = "voting_started"
    VOTING_STOPPED = "voting_stopped"
    TALLY_COMPUTED = "tally_computed"
    DECRYPTION_RECIEVED = "decryption_recieved"
    DECRYPTIONS_COMBINED = "decryptions_combined"
    RESULTS_RELEASED = "results_released"


class ElectionAdminEventEnum(ElectionEventEnum):
    VOTER_LOGIN = "voter_login"
    TRUSTEE_LOGIN = "trustee_login"
    VOTER_LOGIN_FAIL = "voter_login_fail"
    TRUSTEE_LOGIN_FAIL = "trustee_login_fail"


class ElectionLoginTypeEnum(str, enum.Enum):
    close_p = "Close"
    open_p = "Open"
    semi_close_p = "Semi Public"
