# app.py
from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
from web3 import Web3
from models import Voter, Admin, session
from face_utils import encode_face, compare_faces, detect_face_opencv, hash_encoding
import numpy as np
import os, json, base64, cv2, bcrypt, jwt, datetime
from functools import wraps

from config.secret import JWT_SECRET, ADMIN_PRIVATE_KEY, ADMIN_ACCOUNT, CONTRACT_ADDRESS, ABI_PATH, RPC_URL

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_PATH = os.path.join(BASE_DIR, "../frontend")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__, static_folder=FRONTEND_PATH, static_url_path="")
CORS(app)

# ---------------- Web3 setup ----------------
w3 = Web3(Web3.HTTPProvider(RPC_URL))
print("Blockchain connected:", w3.is_connected())

with open(ABI_PATH, "r", encoding="utf-8") as f:
    contract_json = json.load(f)
abi = contract_json if isinstance(contract_json, list) else contract_json.get("abi")
contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=abi)


# ---------------- helpers ----------------

def get_bytes(val):
    """Convert memoryview/bytearray/bytes → bytes"""
    if isinstance(val, bytes):
        return val
    if isinstance(val, bytearray):
        return bytes(val)
    if isinstance(val, memoryview):
        return val.tobytes()
    try:
        return bytes(val)
    except:
        return b""


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Token missing"}), 401

        try:
            token = token.replace("Bearer ", "").strip()
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            username = payload.get("username")

            admin = session.query(Admin).filter_by(username=username).first()
            if not admin:
                return jsonify({"error": "Admin not found"}), 401

            g.admin = admin
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception as e:
            return jsonify({"error": "Invalid token", "detail": str(e)}), 401

        return f(*args, **kwargs)
    return wrapper


def save_image_b64(data_url, dest):
    if "," in data_url:
        _, encoded = data_url.split(",", 1)
    else:
        encoded = data_url

    img_bytes = base64.b64decode(encoded)
    nparr = np.frombuffer(img_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Invalid base64 image")

    cv2.imwrite(dest, img)
    return dest


# ---------------- Frontend pages ----------------

@app.route("/")
def home():
    return send_from_directory(FRONTEND_PATH, "index.html")

@app.route("/admin")
def admin_page():
    return send_from_directory(FRONTEND_PATH, "admin_login.html")

@app.route("/admin-dashboard")
def admin_dashboard():
    return send_from_directory(FRONTEND_PATH, "admin.html")

@app.route("/candidate")
def candidate_page():
    return send_from_directory(FRONTEND_PATH, "candidate.html")

@app.route("/voter")
def voter_page():
    return send_from_directory(FRONTEND_PATH, "voter.html")

@app.route("/results")
def results_page():
    return send_from_directory(FRONTEND_PATH, "results.html")

@app.route("/<path:filename>")
def serve_static(filename):
    return send_from_directory(FRONTEND_PATH, filename)


# ---------------- Admin login step-1 ----------------

@app.route("/admin/login_step1", methods=["POST"])
def admin_login_step1():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")

    admin = session.query(Admin).filter_by(username=username).first()
    if not admin:
        return jsonify({"error": "Invalid username"}), 401

    if not bcrypt.checkpw(password.encode(), admin.password_hash.encode()):
        return jsonify({"error": "Wrong password"}), 401

    return jsonify({"ok": True})


# ---------------- Admin face login ----------------

@app.route("/admin/login_face", methods=["POST"])
def admin_login_face():
    username = request.form.get("username")
    image_b64 = request.form.get("image")

    admin = session.query(Admin).filter_by(username=username).first()
    if not admin:
        return jsonify({"error": "Unknown admin"}), 404

    tmp = os.path.join(UPLOAD_FOLDER, f"admin_face_{username}.jpg")
    save_image_b64(image_b64, tmp)

    faces, img, gray = detect_face_opencv(tmp)
    if len(faces) == 0:
        os.remove(tmp)
        return jsonify({"error": "No face detected"}), 400

    known = get_bytes(admin.face_encoding)
    if not compare_faces(known, tmp):
        os.remove(tmp)
        return jsonify({"error": "Face mismatch"}), 401

    os.remove(tmp)

    token = jwt.encode({
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=4)
    }, JWT_SECRET, algorithm="HS256")

    return jsonify({"ok": True, "token": token})


# ---------------- Add Candidate ----------------

@app.route("/admin/add_candidate", methods=["POST"])
@admin_required
def add_candidate():
    data = request.get_json() or {}
    name = data.get("name")

    try:
        nonce = w3.eth.get_transaction_count(ADMIN_ACCOUNT)
        tx = contract.functions.addCandidate(name).build_transaction({
            "from": ADMIN_ACCOUNT,
            "nonce": nonce,
            "gas": 300000,
            "gasPrice": w3.to_wei("1", "gwei")
        })

        signed = w3.eth.account.sign_transaction(tx, private_key=ADMIN_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)

        w3.eth.wait_for_transaction_receipt(tx_hash)
        return jsonify({"ok": True, "tx": tx_hash.hex()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- List Voters ----------------

@app.route("/admin/voters", methods=["GET"])
@admin_required
def voters_list():
    voters = session.query(Voter).all()
    out = [{"id": v.id, "enrollment": v.enrollment, "name": v.name} for v in voters]
    return jsonify(out)


# ---------------- Register Voter ----------------

@app.route("/admin/register_voter_camera", methods=["POST"])
@admin_required
def register_voter_camera():
    enrollment = request.form.get("enrollment")
    name = request.form.get("name")
    image_b64 = request.form.get("image")

    img_path = os.path.join(UPLOAD_FOLDER, f"{enrollment}.jpg")
    save_image_b64(image_b64, img_path)

    faces, img, gray = detect_face_opencv(img_path)
    if len(faces) == 0:
        os.remove(img_path)
        return jsonify({"error": "No face detected"}), 400

    enc = encode_face(img_path)

    # DB duplicate check
    for v in session.query(Voter).all():
        if compare_faces(get_bytes(v.face_encoding), img_path):
            os.remove(img_path)
            return jsonify({"error": "Face already registered"}), 400

    # Blockchain register
    face_hash = hash_encoding(enc)
    face_hash_bytes32 = Web3.to_bytes(hexstr=face_hash)

    try:
        nonce = w3.eth.get_transaction_count(ADMIN_ACCOUNT)
        tx = contract.functions.registerVoter(enrollment, face_hash_bytes32).build_transaction({
            "from": ADMIN_ACCOUNT,
            "nonce": nonce,
            "gas": 350000,
            "gasPrice": w3.to_wei("1", "gwei")
        })

        signed = w3.eth.account.sign_transaction(tx, private_key=ADMIN_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
    except Exception as e:
        os.remove(img_path)
        return jsonify({"error": str(e)}), 500

    voter = Voter(enrollment=enrollment, name=name, face_encoding=enc.tobytes())
    session.add(voter)
    session.commit()

    os.remove(img_path)
    return jsonify({"ok": True})


# ---------------- Vote Endpoint ----------------

@app.route("/vote", methods=["POST"])
def vote():
    enrollment = request.form.get("enrollment")
    candidate_id = request.form.get("candidate_id")
    image_b64 = request.form.get("image")

    voter = session.query(Voter).filter_by(enrollment=enrollment).first()
    if not voter:
        return jsonify({"error": "Voter not found"}), 404

    tmp = os.path.join(UPLOAD_FOLDER, f"{enrollment}_vote.jpg")
    save_image_b64(image_b64, tmp)

    faces, img, gray = detect_face_opencv(tmp)
    if len(faces) == 0:
        os.remove(tmp)
        return jsonify({"error": "No face detected"}), 400

    if not compare_faces(get_bytes(voter.face_encoding), tmp):
        os.remove(tmp)
        return jsonify({"error": "Face mismatch"}), 401

    enc = encode_face(tmp)
    face_hash = hash_encoding(enc)
    face_hash_bytes32 = Web3.to_bytes(hexstr=face_hash)

    try:
        nonce = w3.eth.get_transaction_count(ADMIN_ACCOUNT)
        tx = contract.functions.vote(enrollment, face_hash_bytes32, int(candidate_id)).build_transaction({
            "from": ADMIN_ACCOUNT,
            "nonce": nonce,
            "gas": 350000,
            "gasPrice": w3.to_wei("1", "gwei")
        })

        signed = w3.eth.account.sign_transaction(tx, private_key=ADMIN_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)

        os.remove(tmp)
        return jsonify({"ok": True, "tx": tx_hash.hex()})
    except Exception as e:
        os.remove(tmp)
        return jsonify({"error": str(e)}), 500


# ---------------- Candidates List ----------------

@app.route("/candidates")
def candidates_list():
    total = contract.functions.candidateCount().call()
    out = []
    for i in range(1, total + 1):
        cid, name, votes = contract.functions.getCandidate(i).call()
        out.append({"id": cid, "name": name, "votes": votes})
    return jsonify(out)


# ---------------- Run Server ----------------

if __name__ == "__main__":
    print("Server running at http://127.0.0.1:5000")
    app.run(debug=True)
