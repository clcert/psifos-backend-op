"""
Utilities for Psifos.

08-04-2022
"""

import json
from app.psifos.crypto.sharedpoint import Point

from functools import reduce

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
    return [Point.serialize(x.point, to_json=False) for x in points]

# -- Election utils --

def generate_election_pk(trustees):
    a_combined_pk = trustees[0].coefficients.instances[0].coefficient
    for t in trustees[1:]:
        a_combined_pk = combined_pk * t.coefficients.instances[0].coefficient

    t_first_coefficients = [t.coefficients.instances[0].coefficient for t in trustees]

    combined_pk = reduce((lambda x, y: x * y), t_first_coefficients)
    return trustees[0].public_key.clone_with_new_y(combined_pk)


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



