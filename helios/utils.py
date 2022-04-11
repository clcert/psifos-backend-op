"""
Utilities for Psifos.

08-04-2022
"""

from math import exp
from helios.serialization import SerializableObject
from flask import abort
from helios.models import Election
from functools import update_wrapper
class TestObject(SerializableObject):
    """
    Allows testing object serializarion.
    """
    def __init__(self, public_key = None, secret_key = None) -> None:
        self.public_key = public_key
        self.secret_key = secret_key

def __verify_election_status(election, expected_status):
    """
    Verifies the election status is coherent with the status
    indicated in the decorator.

    Currently supports:
        - frozen check
    """

    frozen = expected_status.get("frozen", None)
    if frozen is None:
        return

    if frozen and not election.frozen_at:
        abort(403)
    if not frozen and election.frozen_at:
        abort(403)


def election_route(**status):
    """
    Route decorator, allows the developer to directly use the election instance
    if it is available instead of querying the database using the election_uuid.
    """

    def election_route_decorator(func):
        def election_route_wrapper(current_user, election_uuid=None, *args, **kwargs):
            query = Election.filter_by(uuid=election_uuid)
            if len(query) == 0:
                abort(404)
            election = query[0]

            __verify_election_status(election, status)

            # TODO: implement CAS redirect if election is private.
        
            return func(current_user, election, *args, **kwargs)

        return update_wrapper(election_route_wrapper, func)

    return election_route_decorator