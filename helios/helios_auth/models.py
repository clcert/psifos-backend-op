from helios import db


class User(db.Model):

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

    def __repr__(self):
        return '<User %r>' % self.id

    def get_id(self):
        return self.id
