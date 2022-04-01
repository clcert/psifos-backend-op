from helios import db
from helios.models import TestModel
from helios.schemas import TestSchema
from helios.utils import TestObject

db.drop_all()
db.create_all()

# 1. PsifosModel Tests:

test_object = TestObject(public_key="123", secret_key="321")
test_model = TestModel(id=1, test_object=test_object)
test_schema = TestSchema()

# 1.1 PsifosModel.serialize(...)
print("PsifosModel.serialize")
json_data = TestModel.serialize(test_schema, test_model)
print(json_data)

# 1.2 PsifosModel.deserialize(...)
print("PsifosModel.deserialize")
a_test_model = TestModel.deserialize(test_schema, json_data)
print(a_test_model.id, a_test_model.test_object.public_key, a_test_model.test_object.secret_key)

# 1.3 TestModel.save(...)
print("PsifosModel.save")
TestModel.save(test_schema, test_model)
a_query = TestModel.query.filter_by(id=1)
print(a_query.count())

# 1.4 TestModel.execute(...)
print("PsifosModel.execute")
a_query = TestModel.execute(test_schema, TestModel.query.filter_by, id=1)
a_test_model = a_query[0]
print(a_test_model.id, a_test_model.test_object.public_key, a_test_model.test_object.secret_key)
