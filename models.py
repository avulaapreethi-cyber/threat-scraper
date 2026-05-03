from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Threat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(50), unique=True)
    severity = db.Column(db.String(20))
    score = db.Column(db.Float)
    description = db.Column(db.Text)

    def __repr__(self):
        return f"<CVE {self.cve_id}>"