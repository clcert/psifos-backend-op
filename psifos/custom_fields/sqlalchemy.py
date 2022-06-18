import re
import sqlalchemy.types as types


class SerializableField(types.TypeDecorator):
    impl = types.Text

    def __init__(self, class_type, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.class_type = class_type

    def process_bind_param(self, value, dialect):
        if value is None:
            return ""

        return self.class_type.serialize(value)

    def process_result_value(self, value, dialect):
        if value == "":
            return None

        return self.class_type.deserialize(value)
