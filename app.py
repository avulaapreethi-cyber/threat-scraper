from flask import Flask, render_template
from models import db, Threat
from fetcher import fetch_and_store

app = Flask(__name__)

# SQLite database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///threats.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

@app.route("/")
def index():
    threats = Threat.query.order_by(Threat.score.desc()).all()
    return render_template("index.html", threats=threats)

@app.route("/update")
def update():
    fetch_and_store()
    return "✅ Database updated!"

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)