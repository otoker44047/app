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
app.secret_key = 'key'      # for Flask sessions
JWT_SECRET    = 'key'
USERNAME      = 'CNS-user'
PASSWORD      = 'CNS-password'

# make session cookies HttpOnly
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False    # set True if you deploy over HTTPS
)


#
# ————————————————
# 1) Cookie‐based login
# ————————————————
# @app.route('/login', methods=['POST'])
# def login_cookie():
#     data = request.get_json() or {}
#     if data.get('username') == USERNAME and data.get('password') == PASSWORD:
#         session.clear()
#         session['authenticated'] = True
#         session['username']      = USERNAME
#         return '', 200
#     return abort(401)
#
#
# #
# # ————————————————
# # 2) JWT‐based login
# # ————————————————
# @app.route('/login-jwt', methods=['POST'])
# def login_jwt():
#     data = request.get_json() or {}
#     if data.get('username') == USERNAME and data.get('password') == PASSWORD:
#         payload = {
#             'username': USERNAME,
#             'exp':      datetime.datetime.utcnow() + datetime.timedelta(hours=1)
#         }
#         token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
#         return jsonify(token=token), 200
#     return abort(401)
#
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
    user, pw = parts
    return user == USERNAME and pw == PASSWORD
#
# #
# # ————————————————
# # 3) Protected root “/”
# #    accepts any of:
# #      • valid Flask session cookie
# #      • Basic auth header
# #      • Bearer (JWT) header
# # ————————————————
# @app.route('/', methods=['GET'])
# def index():
#     # A) cookie/session
#     if session.get('authenticated'):
#         return f"Hello {session['username']} (cookie)", 200
#
#     # read Authorization header
#     auth_header = request.headers.get('Authorization', None)
#     if not check_auth(auth_header):
#         return authenticate()
#     return "OK\n", 200


# --- NEW helper --------------------------------------------------------------
def _extract_basic_credentials(req):
    """Return (user, pw) tuple if Authorization: Basic ... present; else (None,None)."""
    hdr = req.headers.get("Authorization", "")
    if hdr.startswith("Basic "):
        try:
            userpw = base64.b64decode(hdr[6:]).decode()
            return userpw.split(":", 1)
        except Exception:
            pass
    return (None, None)

# --- REPLACE all /login* routes by ONE universal /login ----------------------
@app.route("/login", methods=["GET", "POST"])
def universal_login():
    # 1️⃣ Accept either Basic-Auth header **or** JSON body
    user, pw = _extract_basic_credentials(request)
    if user is None:               # fall back to JSON
        data = request.get_json(silent=True) or {}
        user, pw = data.get("username"), data.get("password")

    if user != USERNAME or pw != PASSWORD:
        return abort(401)

    # 2️⃣ COOKIE branch – always create a session
    session.clear()
    session["authenticated"] = True
    session["username"]      = USERNAME

    # 3️⃣ JWT branch – always create a token (subtask “c” will read it)
    payload = {
        "username": USERNAME,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    # 4️⃣ Single unified response
    # • Sets Flask session cookie (for subtask b)  
    # • Returns JSON with token (for subtask c)
    return jsonify(token=token), 200

    

# --- PATCH the protected resource -------------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    # a) Cookie/session check  (subtask b)
    if request.method == "GET":
        if session.get("authenticated"):
            return f"Hello {session['username']} (cookie)\n", 200

        # b) JWT Bearer check      (subtask c)
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            try:
                jwt.decode(auth[7:], JWT_SECRET, algorithms=["HS256"])
                return "Hello JWT user\n", 200
            except jwt.PyJWTError:
                pass  # fall through → 401

        # c) HTTP Basic check      (subtask a)
        if check_auth(auth):
            return "Hello Basic user\n", 200

        # Otherwise request auth
        return authenticate()
    elif request.method == "POST":
        body = request.get_json(silent=True) or {}
        user = body.get("username")
        pw = body.get("password")

        if user is None and request.headers.get("Authorization", "").startswith("Basic "):
            user, pw = _extract_basic_credentials(request)
        if user == USERNAME and pw == PASSWORD:
            session.clear()
            session["authenticated"] = True
            session["username"] = user

            payload = {
                    "username": USERNAME,
                    "iat": datetime.datetime.utcnow(),
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
            }
            token = jwt.encode(payload, JWT_SECRET, alrogithm="HS256")
            resp = jsonify(token=token)
            return resp, 200
        return abort(401)



if __name__ == '__main__':
    PORT = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=PORT)

