"""
Serialization for Psifos objects.

01-04-2022
"""

from __future__ import annotations
import json
from copy import copy


class SerializableList(object):
    """ 
    This class is an abstraction layer for serialization
    and deserialization of list of SerializableObjects.
    """

    def __init__(self) -> None:
        self.instances = []

    @classmethod
    def serialize(cls, s_list: SerializableList = None, to_json: bool = True) -> str:
        """ 
        Serializes an object to a JSON like string. 
        """

        if s_list is None:
            return '[]'

        if isinstance(s_list, str):
            return s_list

        a_list = copy(s_list)
        serialized_instances = []
        for obj in a_list.instances:
            if isinstance(obj, SerializableObject) or isinstance(obj, SerializableList):
                obj_class = obj.__class__
                serialized_instances.append(obj_class.serialize(obj, to_json=False))
            elif isinstance(obj, int):
                serialized_instances.append(str(obj))

        return json.dumps(serialized_instances) if to_json else serialized_instances

    @classmethod
    def deserialize(cls, json_data: str = '[]') -> SerializableObject:
        """ 
        Deserializes a JSON like string to a specific 
        class instance. 
        """
        return cls(*json.loads(json_data))
    
    def set_instances(self, new_instances):
        self.instances = new_instances


class SerializableObject(object):
    """ 
    This class is an abstraction layer for serialization
    and deserialization of an object.
    """

    @classmethod
    def serialize(cls, obj: SerializableObject = None, to_json=True) -> str:
        """ 
        Serializes an object to a JSON like string. 
        """

        if obj is None:
            return '{}'

        if isinstance(obj, str):
            return obj

        a_obj = copy(obj)
        class_attributes = [attr for attr in dir(a_obj) if not attr.startswith("_")]
        for attr in class_attributes:
            attr_value = getattr(a_obj, attr)
            if isinstance(attr_value, SerializableObject) or isinstance(attr_value, SerializableList):
                attr_class = attr_value.__class__
                serialized_attr = attr_class.serialize(attr_value, to_json=False)
                setattr(a_obj, attr, serialized_attr)
            elif isinstance(attr_value, int):
                serialized_attr = str(attr_value)
                setattr(a_obj, attr, serialized_attr)

        filtered_dict = {
            key: value for key, value in a_obj.__dict__.items()
            if not key.startswith("_")
        }
        return json.dumps(filtered_dict) if to_json else filtered_dict

    @classmethod
    def deserialize(cls, json_data: str = '{}') -> SerializableObject:
        """ 
        Deserializes a JSON like string to a specific 
        class instance. 
        """
        return cls(**json.loads(json_data))
