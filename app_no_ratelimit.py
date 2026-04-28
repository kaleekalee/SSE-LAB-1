from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

bcrypt = Bcrypt(app)

# ---------------- DATABASE MODEL ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    otp_secret = db.Column(db.String(200))

with app.app_context():
    db.create_all()

# ---------------- REGISTER ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_pw = bcrypt.generate_password_hash(
            request.form['password']
        ).decode('utf-8')

        secret = pyotp.random_base32()

        user = User(
            username=request.form['username'],
            password=hashed_pw,
            otp_secret=secret
        )

        db.session.add(user)
        db.session.commit()

        return redirect('/login')

    return render_template("register.html")

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()

        if not user:
            return "User not found"

        if bcrypt.check_password_hash(user.password, request.form['password']):
            session['user'] = user.username
            return redirect('/2fa')

        return "Invalid credentials"

    return render_template("login.html")

# ---------------- 2FA QR CODE ----------------
@app.route('/2fa')
def twofa():
    user = User.query.filter_by(username=session['user']).first()

    totp = pyotp.TOTP(user.otp_secret)

    uri = totp.provisioning_uri(
        name=user.username,
        issuer_name="SecureApp"
    )

    qr = qrcode.make(uri)

    buf = io.BytesIO()
    qr.save(buf)
    img_str = base64.b64encode(buf.getvalue()).decode()

    return render_template("verify_2fa.html", qr=img_str)

# ---------------- VERIFY OTP ----------------
@app.route('/verify', methods=['POST'])
def verify():
    user = User.query.filter_by(username=session['user']).first()
    otp = request.form['otp']

    totp = pyotp.TOTP(user.otp_secret)

    if totp.verify(otp):
        return "LOGIN SUCCESSFUL WITH 2FA"
    else:
        return "INVALID OTP"

# ---------------- RUN APP ----------------
if __name__ == "__main__":
    app.run(debug=True)
