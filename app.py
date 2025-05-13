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

        if not user:
            user, pw = request.form.get("username"), request.form.get("password")

        if user == USERNAME and pw == PASSWORD:
            session.clear()
            session["authenticated"] = True
            session["username"] = user

            payload = {
                    "username": USERNAME,
                    "iat": datetime.datetime.utcnow(),
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
            }
            token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
            resp = jsonify(token=token)
            return token, 200, {"Content-Type": "text/plain"}
            #return resp, 200
        return abort(401)

    return "", 200

@app.before_request
def dbg():
    print(request.method, request.path, dict(request.headers))

if __name__ == '__main__':
    PORT = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=PORT)

