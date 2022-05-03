"""
Serialization for Psifos objects.

01-04-2022
"""

from __future__ import annotations
import json


class SerializableList(object):
    """ 
    This class is an abstraction layer for serialization
    and deserialization of an untyped list of SerializableObjects 
    created by the same Factory (Factory Method Design Pattern).

    To ensure the serialization/deseralization works correctly, 
    a SerializableList MUST construct its instances by using
    a factory.

    Ex: See class psifos.psifos_object.questions.Questions
    """

    instances = []

    @classmethod
    def serialize(cls, s_list: SerializableObject) -> str:
        """ 
        Serializes an object to a JSON like string. 
        """

        if isinstance(s_list, str):
            return s_list

        serialized_instances = [SerializableObject.serialize(obj) for obj in s_list.instances]
        return json.dumps(serialized_instances)

    @classmethod
    def deserialize(cls, json_data: str) -> SerializableObject:
        """ 
        Deserializes a JSON like string to a specific 
        class instance. 
        """
        serialized_instances = [json.loads(q) for q in json.loads(json_data)]
        return cls(*serialized_instances)


class SerializableObject(object):
    """ 
    This class is an abstraction layer for serialization
    and deserialization of an object.
    """

    @classmethod
    def serialize(cls, obj: SerializableObject) -> str:
        """ 
        Serializes an object to a JSON like string. 
        """

        if isinstance(obj, str):
            return obj

        return json.dumps(obj.__dict__)

    @classmethod
    def deserialize(cls, json_data: str) -> SerializableObject:
        """ 
        Deserializes a JSON like string to a specific 
        class instance. 
        """
        return cls(**json.loads(json_data))
