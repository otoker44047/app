# app.py
from flask import Flask, request, jsonify, session, abort, Response
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

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        "Authentication required\n", 
        401,
        {"WWW-Authenticate": 'Basic realm="CNS Judge"'}
    )

def check_auth(auth_header):
    """
    Returns True if the Authorization header is valid.
    auth_header is the raw header string, e.g. 'Basic QWxhZGRpbjpPcGVuU2VzYW1l'
    """
    if not auth_header or not auth_header.startswith("Basic "):
        return False
    # strip off "Basic "
    b64 = auth_header.split(" ", 1)[1]
    try:
        decoded = base64.b64decode(b64).decode("utf-8")
    except Exception:
        return False
    # Expect format username:password
    parts = decoded.split(":", 1)
    if len(parts) != 2:
        return False
    return True

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
    auth_header = request.headers.get('Authorization', None)
    if not check_auth(auth_header):
        return authenticate()
    return "OK\n", 200
    

if __name__ == '__main__':
    PORT = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=PORT)

