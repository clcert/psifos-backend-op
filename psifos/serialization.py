"""
Serialization for Psifos objects.

01-04-2022
"""

from __future__ import annotations
import json


class SerializableList(object):
    """ 
    This class is an abstraction layer for serialization
    and deserialization of list of SerializableObjects.
    """

    def __init__(self) -> None:
        self.instances = []

    @classmethod
    def serialize(cls, s_list: SerializableList) -> str:
        """ 
        Serializes an object to a JSON like string. 
        """

        if s_list is None:
            return '[]'

        if isinstance(s_list, str):
            return s_list

        serialized_instances = []
        for obj in s_list.instances:
            obj_class = obj.__class__
            serialized_instances.append(obj_class.serialize(obj, to_dict=True))

        return json.dumps(serialized_instances)

    @classmethod
    def deserialize(cls, json_data: str) -> SerializableObject:
        """ 
        Deserializes a JSON like string to a specific 
        class instance. 
        """
        return cls(*json.loads(json_data))


class SerializableObject(object):
    """ 
    This class is an abstraction layer for serialization
    and deserialization of an object.
    """

    @classmethod
    def serialize(cls, obj: SerializableObject, to_dict=False) -> str:
        """ 
        Serializes an object to a JSON like string. 
        """

        if obj is None:
            return '{}'

        if isinstance(obj, str):
            return obj

        class_attributes = [attr for attr in dir(obj) if not attr.startswith("_")]
        for attr in class_attributes:
            try:
                attr_value = getattr(obj, attr)
                attr_class = attr_value.__class__
                serialized_attr = attr_class.serialize(attr_value, to_dict=True)
                setattr(obj, attr, serialized_attr)
            except:
                pass

        return obj.__dict__ if to_dict else json.dumps(obj.__dict__)

    @classmethod
    def deserialize(cls, json_data: str) -> SerializableObject:
        """ 
        Deserializes a JSON like string to a specific 
        class instance. 
        """
        return cls(**json.loads(json_data))
