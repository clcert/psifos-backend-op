"""
Utilities for Psifos.

08-04-2022
"""

import json

from psifos.models import Voter
from psifos.psifos_auth.utils import get_user

# -- JSON manipulation --


def to_json(d: dict):
    return json.dumps(d, sort_keys=True)


def from_json(value):
    if value == "" or value is None:
        return None

    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception as e:
            raise Exception("psifos.utils error: in from_json, value is not JSON parseable") from e

    return value


# -- SharedPoint manipulation --
def format_points(points):
    return [from_json(x.point) for x in points]

# -- CastVote validation --

def do_cast_vote_checks(request, election, voter):
    if not election.voting_has_started():
        return False, "Error al enviar el voto: la eleccion aun no comienza"

    if election.voting_has_ended():
        return False, "Error al enviar el voto: el proceso de voto ha concluido"

    if request.get_json().get("encrypted_vote") is None:
        return False, "Error al enviar el voto: no se envio el encrypted vote"

    if election.private_p:
        if voter is None:
            return False, "Error al enviar el voto: votante no encontrado"
    return True, None



