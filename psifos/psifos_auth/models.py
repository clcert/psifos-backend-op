from psifos import db
from psifos.psifos_model import PsifosModel


class User(db.Model, PsifosModel):

    __tablename__ = "auth_user"

    id = db.Column(db.Integer, primary_key=True)

    # Id for token
    public_id = db.Column(db.String(200))
    user_type = db.Column(db.String(50))
    user_id = db.Column(db.String(100))

    name = db.Column(db.String(200), nullable=True)
    password = db.Column(db.String(200))

    # administrator
    admin_p = db.Column(db.Boolean, default=False)

    # One-to-many relationship
    elections = db.relationship("Election", backref="auth_user")

    def __repr__(self):
        return '<User %r>' % self.id

    def get_id(self):
        return self.id

    @classmethod
    def get_by_name(cls, name):
        query = cls.filter_by(name=name)
        return query[0] if len(query) > 0 else None

    @classmethod
    def get_by_public_id(cls, public_id):
        query = cls.filter_by(public_id=public_id)
        return query[0] if len(query) > 0 else None
