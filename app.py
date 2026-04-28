from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = "supersecretkey"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

bcrypt = Bcrypt(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    otp_secret = db.Column(db.String(200))
    failed_attempts = db.Column(db.Integer, default=0)
    locked = db.Column(db.Boolean, default=False)

with app.app_context():
    db.create_all()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_pw = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        secret = pyotp.random_base32()

        user = User(username=request.form['username'], password=hashed_pw, otp_secret=secret)
        db.session.add(user)
        db.session.commit()

        return redirect('/login')

    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()

        if not user:
            return "User not found"

        if user.locked:
            return "Account locked"

        if bcrypt.check_password_hash(user.password, request.form['password']):
            session['user'] = user.username
            user.failed_attempts = 0
            db.session.commit()
            return redirect('/2fa')

        user.failed_attempts += 1
        if user.failed_attempts >= 3:
            user.locked = True

        db.session.commit()
        return "Invalid credentials"

    return render_template("login.html")


@app.route('/2fa')
def twofa():
    user = User.query.filter_by(username=session['user']).first()
    totp = pyotp.TOTP(user.otp_secret)

    uri = totp.provisioning_uri(name=user.username, issuer_name="SecureApp")

    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf)
    img = base64.b64encode(buf.getvalue()).decode()

    return render_template("verify_2fa.html", qr=img)


@app.route('/verify', methods=['POST'])
def verify():
    user = User.query.filter_by(username=session['user']).first()
    otp = request.form['otp']

    totp = pyotp.TOTP(user.otp_secret)

    if totp.verify(otp):
        return "LOGIN SUCCESSFUL WITH 2FA"
    return "INVALID OTP"


if __name__ == "__main__":
    app.run(debug=True)