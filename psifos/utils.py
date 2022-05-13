"""
Utilities for Psifos.

08-04-2022
"""

import json

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
