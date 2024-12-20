"""
Utilities for Psifos.

08-04-2022
"""

import json

from tkinter.messagebox import RETRY
import pytz

from app.psifos.model.enums import ElectionLoginTypeEnum
from app.psifos.model.cruds import crypto_crud
from app.psifos.crypto.sharedpoint import Point
from datetime import datetime
from app.config import TIMEZONE

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
            raise Exception(
                "psifos.utils error: in from_json, value is not JSON parseable"
            ) from e

    return value


# -- SharedPoint manipulation --
def format_points(points):
    return [Point.serialize(x.point, to_json=False) for x in points]


# -- Election utils --


async def generate_election_pk(trustees, session):
    t_first_coefficients = [t.coefficients.instances[0].coefficient for t in trustees]

    combined_pk = reduce((lambda x, y: x * y), t_first_coefficients)
    public_key = await crypto_crud.get_public_key(session, trustees[0].public_key_id)
    return public_key.clone_with_new_y(combined_pk)


# -- CastVote validation --


def do_cast_vote_checks(request, election, voter):
    if not election.voting_has_started():
        return False, "Error al enviar el voto: la eleccion aun no comienza"

    if election.voting_has_ended():
        return False, "Error al enviar el voto: el proceso de voto ha concluido"

    if request.get_json().get("encrypted_vote") is None:
        return False, "Error al enviar el voto: no se envio el encrypted vote"

    if election.voters_login_type == ElectionLoginTypeEnum.close_p:
        if voter is None:
            return False, "Error al enviar el voto: votante no encontrado"
    return True, None


# -- Datetime --
def tz_now():
    tz = pytz.timezone(TIMEZONE)
    return datetime.now(tz)


