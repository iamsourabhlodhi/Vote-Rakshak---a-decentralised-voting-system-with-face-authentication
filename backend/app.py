# backend/app.py
from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
from web3 import Web3
from models import Voter, Admin, SessionLocal
from face_utils import encode_face, compare_faces, hash_encoding
import numpy as np
import os, json, base64, cv2, bcrypt, jwt, datetime
from functools import wraps

from config.secret import (
    JWT_SECRET,
    ADMIN_PRIVATE_KEY,
    ADMIN_ACCOUNT,
    CONTRACT_ADDRESS,
    ABI_PATH,
    RPC_URL,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_PATH = os.path.join(BASE_DIR, "../frontend")   # backend/ .. /frontend
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__, static_folder=FRONTEND_PATH, static_url_path="")
CORS(app)

# ---------------- Blockchain Setup ----------------
w3 = Web3(Web3.HTTPProvider(RPC_URL))
print("Blockchain Connected:", w3.is_connected())

with open(ABI_PATH, "r", encoding="utf-8") as f:
    contract_json = json.load(f)
abi = contract_json if isinstance(contract_json, list) else contract_json.get("abi")

contract = w3.eth.contract(
    address=Web3.to_checksum_address(CONTRACT_ADDRESS),
    abi=abi,
)

# ---------------- Helpers ----------------
def get_bytes(val):
    if isinstance(val, (bytes, bytearray, memoryview)):
        return bytes(val)
    return bytes(val) if val is not None else b""


def save_image_b64(data_url, dest):
    """
    data_url: "data:image/jpeg;base64,...." OR pure base64 string
    return: numpy BGR image
    """
    if "," in data_url:
        _, encoded = data_url.split(",", 1)
    else:
        encoded = data_url

    img_bytes = base64.b64decode(encoded)
    nparr = np.frombuffer(img_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    if img is None:
        raise ValueError("Invalid Base64 image")

    cv2.imwrite(dest, img)
    return img


def safe_delete(path):
    try:
        if os.path.exists(path):
            os.remove(path)
    except:
        pass


def send_contract_tx(fn, *args, gas=350000):
    """
    Helper to send tx & catch revert messages nicely.
    Returns (tx_hash_str, error_str)
    """
    try:
        nonce = w3.eth.get_transaction_count(ADMIN_ACCOUNT)
        tx = fn(*args).build_transaction(
            {
                "from": ADMIN_ACCOUNT,
                "nonce": nonce,
                "gas": gas,
                "gasPrice": w3.to_wei("1", "gwei"),
            }
        )
        signed = w3.eth.account.sign_transaction(tx, private_key=ADMIN_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
        # optional: wait for receipt
        # w3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_hash.hex(), None
    except ValueError as e:
        err = e.args[0]
        reason = ""
        if isinstance(err, dict):
            # Ganache style
            reason = (
                err.get("data", {}).get("reason")
                or err.get("data", {}).get("message")
                or err.get("message", "")
            )
        else:
            reason = str(err)
        return None, reason or "Blockchain error"
    except Exception as e:
        return None, str(e)


# ---------------- Auth Decorator ----------------
def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Token missing"}), 401

        try:
            token = token.replace("Bearer ", "").strip()
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            username = payload.get("username")

            with SessionLocal() as db:
                admin = db.query(Admin).filter_by(username=username).first()
                if not admin:
                    return jsonify({"error": "Admin not found"}), 401
                g.admin = admin  # rarely used, but kept
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception as e:
            return jsonify({"error": "Invalid token", "detail": str(e)}), 401

        return f(*args, **kwargs)

    return wrap


# ---------------- Frontend Routes ----------------
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
def static_files(filename):
    return send_from_directory(FRONTEND_PATH, filename)


# ---------------- Admin Login Step 1 (Password) ----------------
@app.route("/admin/login_step1", methods=["POST"])
def admin_login_step1():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")

    with SessionLocal() as db:
        admin = db.query(Admin).filter_by(username=username).first()

    if not admin:
        return jsonify({"error": "Invalid username"}), 401

    if not bcrypt.checkpw(password.encode(), admin.password_hash.encode()):
        return jsonify({"error": "Wrong password"}), 401

    return jsonify({"ok": True})


# ---------------- Admin Face Login ----------------
@app.route("/admin/login_face", methods=["POST"])
def admin_login_face():
    username = request.form.get("username")
    image_b64 = request.form.get("image")

    with SessionLocal() as db:
        admin = db.query(Admin).filter_by(username=username).first()

    if not admin:
        return jsonify({"error": "Unknown admin"}), 404

    tmp_path = os.path.join(UPLOAD_FOLDER, f"admin_{username}.jpg")

    try:
        img = save_image_b64(image_b64, tmp_path)  # numpy BGR image
        known_bytes = get_bytes(admin.face_encoding)

        if not compare_faces(known_bytes, img):
            safe_delete(tmp_path)
            return jsonify({"error": "Face mismatch"}), 401

        safe_delete(tmp_path)

        token = jwt.encode(
            {
                "username": username,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=4),
            },
            JWT_SECRET,
            algorithm="HS256",
        )

        return jsonify({"ok": True, "token": token})

    except Exception as e:
        safe_delete(tmp_path)
        return jsonify({"error": "Face login failed", "detail": str(e)}), 500


# ---------------- Add Candidate ----------------
@app.route("/admin/add_candidate", methods=["POST"])
@admin_required
def add_candidate():
    data = request.get_json() or {}
    name = data.get("name")

    tx_hash, err = send_contract_tx(contract.functions.addCandidate, name, gas=300000)
    if err:
        return jsonify({"error": err}), 500

    return jsonify({"ok": True, "tx": tx_hash})


# ---------------- List Voters (Admin Panel) ----------------
@app.route("/admin/voters", methods=["GET"])
@admin_required
def voters_list():
    with SessionLocal() as db:
        voters = db.query(Voter).all()
        out = [
            {"id": v.id, "enrollment": v.enrollment, "name": v.name} for v in voters
        ]
    return jsonify(out)


# ---------------- Register Voter via Camera ----------------
@app.route("/admin/register_voter_camera", methods=["POST"])
@admin_required
def register_voter_camera():
    enrollment = request.form.get("enrollment")
    name = request.form.get("name")
    image_b64 = request.form.get("image")

    if not enrollment or not name or not image_b64:
        return jsonify({"error": "All fields required"}), 400

    img_path = os.path.join(UPLOAD_FOLDER, f"temp_{enrollment}.jpg")

    with SessionLocal() as db:
        # Enrollment unique check
        if db.query(Voter).filter_by(enrollment=enrollment).first():
            return jsonify({"error": "Enrollment already registered"}), 409

        try:
            img = save_image_b64(image_b64, img_path)

            # New encoding for this voter
            new_enc = encode_face(img)

            # Face duplicate check
            existing_voters = db.query(Voter).all()
            for v in existing_voters:
                if compare_faces(get_bytes(v.face_encoding), img):
                    safe_delete(img_path)
                    return jsonify({"error": "This face already registered"}), 409

            # Blockchain: store hash
            face_hash = hash_encoding(new_enc)
            face_hash_bytes32 = Web3.to_bytes(hexstr=face_hash)

            tx_hash, err = send_contract_tx(
                contract.functions.registerVoter, enrollment, face_hash_bytes32
            )
            if err:
                safe_delete(img_path)
                return jsonify({"error": err}), 500

            # Store in DB
            voter = Voter(
                enrollment=enrollment,
                name=name,
                face_encoding=new_enc.tobytes(),
            )
            db.add(voter)
            db.commit()

            safe_delete(img_path)
            return jsonify({"ok": True, "tx": tx_hash})

        except Exception as e:
            db.rollback()
            safe_delete(img_path)
            return jsonify({"error": str(e)}), 500


# ---------------- Cast Vote ----------------
@app.route("/vote", methods=["POST"])
def vote():
    enrollment = request.form.get("enrollment")
    candidate_id = request.form.get("candidate_id")
    image_b64 = request.form.get("image")

    if not enrollment or not candidate_id or not image_b64:
        return jsonify({"error": "All fields required"}), 400

    tmp_path = os.path.join(UPLOAD_FOLDER, f"{enrollment}_vote.jpg")

    with SessionLocal() as db:
        voter = db.query(Voter).filter_by(enrollment=enrollment).first()
        if not voter:
            return jsonify({"error": "Voter not found"}), 404

        try:
            img = save_image_b64(image_b64, tmp_path)

            # Face verify
            if not compare_faces(get_bytes(voter.face_encoding), img):
                safe_delete(tmp_path)
                return jsonify({"error": "Face mismatch"}), 401

            # New encoding + hash for blockchain proof
            new_enc = encode_face(img)
            face_hash = hash_encoding(new_enc)
            face_hash_bytes32 = Web3.to_bytes(hexstr=face_hash)

            tx_hash, err = send_contract_tx(
                contract.functions.vote,
                enrollment,
                face_hash_bytes32,
                int(candidate_id),
            )

            safe_delete(tmp_path)

            if err:
                # Special case: already voted
                if "already voted" in err.lower():
                    return jsonify({"error": "You already voted"}), 400
                return jsonify({"error": err}), 500

            return jsonify({"ok": True, "tx": tx_hash})

        except Exception as e:
            safe_delete(tmp_path)
            return jsonify({"error": "Vote failed", "detail": str(e)}), 500


# ---------------- Candidates ----------------
@app.route("/candidates")
def candidates_list():
    total = contract.functions.candidateCount().call()
    out = []
    for i in range(1, total + 1):
        cid, name, votes = contract.functions.getCandidate(i).call()
        out.append({"id": cid, "name": name, "votes": votes})
    return jsonify(out)


# ---------------- Run ----------------
if __name__ == "__main__":
    print("\n🚀 Server running at http://127.0.0.1:5000\n")
    app.run(debug=True)
