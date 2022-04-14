from marshmallow import fields

class JSONField(fields.Field):
    """
    Extension of a marshmallow Field to support JSONFields.
    """
    def __init__(self, class_type, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.class_type = class_type

    def _serialize(self, value, attr, obj, **kwargs):
        """
        This method gets called in the background when we
        serialize a Psifos Model instance. It's called for 
        each JSONField in it's schema.
        """
        if value is None:
            return ""

        return self.class_type.serialize(value)

    def _deserialize(self, value, attr, data, **kwargs):
        """
        Same as _serialize but for deserializing.
        """
        return self.class_type.deserialize(value)