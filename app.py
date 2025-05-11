# app.py
from flask import Flask, request, jsonify, session, abort
import os
import base64
import datetime
import jwt  # PyJWT

app = Flask(__name__)

#
# ————————————————
# Configuration / “DB”
# ————————————————
app.secret_key = 'replace_with_a_real_secret_key'      # for Flask sessions
JWT_SECRET    = 'replace_with_a_real_jwt_secret'
USERNAME      = 'user'
PASSWORD      = 'password'

# make session cookies HttpOnly
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False    # set True if you deploy over HTTPS
)


#
# ————————————————
# 1) Cookie‐based login
# ————————————————
@app.route('/login-cookie', methods=['POST'])
def login_cookie():
    data = request.get_json() or {}
    if data.get('username') == USERNAME and data.get('password') == PASSWORD:
        session.clear()
        session['authenticated'] = True
        session['username']      = USERNAME
        return '', 200
    return abort(401)


#
# ————————————————
# 2) JWT‐based login
# ————————————————
@app.route('/login-jwt', methods=['POST'])
def login_jwt():
    data = request.get_json() or {}
    if data.get('username') == USERNAME and data.get('password') == PASSWORD:
        payload = {
            'username': USERNAME,
            'exp':      datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
        return jsonify(token=token), 200
    return abort(401)


#
# ————————————————
# 3) Protected root “/”
#    accepts any of:
#      • valid Flask session cookie
#      • Basic auth header
#      • Bearer (JWT) header
# ————————————————
@app.route('/', methods=['GET'])
def index():
    # A) cookie/session
    if session.get('authenticated'):
        return f"Hello {session['username']} (cookie)", 200

    # read Authorization header
    auth = request.headers.get('Authorization', '')
    parts = auth.split(' ', 1)

    # B) Basic
    if len(parts) == 2 and parts[0] == 'Basic':
        try:
            decoded = base64.b64decode(parts[1]).decode('utf-8')
            user, pw = decoded.split(':', 1)
        except Exception:
            return abort(401)
        if user == USERNAME and pw == PASSWORD:
            return f"Hello {user} (basic)", 200
        return abort(401)

    # C) Bearer / JWT
    if len(parts) == 2 and parts[0] == 'Bearer':
        token = parts[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            user = payload.get('username')
            return f"Hello {user} (jwt)", 200
        except jwt.ExpiredSignatureError:
            return abort(401)
        except jwt.InvalidTokenError:
            return abort(401)

    # no valid auth
    return abort(401)


if __name__ == '__main__':
    PORT = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=PORT)

