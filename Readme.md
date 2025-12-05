🗳 Decentralized Voting System with Facial Authentication

A secure, tamper-proof blockchain-based voting platform that authenticates voters using live facial recognition and stores votes on the Ethereum blockchain.

This system ensures:

✔ One person = one vote
✔ Live camera authentication (no fake image upload)
✔ Transparent & immutable vote recording
✔ Secure admin panel with face login
✔ Fully decentralized vote counting

🚀 Features
🔒 1. Admin Authentication (3-Level Security)

Username

Password (bcrypt hashed)

Live Face Verification

🧑‍💼 2. Admin Dashboard

Add new candidates (stored on blockchain)

Register voters with face capture

View all registered voters

🧑‍🎓 3. Voter Registration

Enrollment number & full name

Live camera capture

Extracts 128-D face embedding

Stores:

Full embedding → MySQL

SHA-256 hash → Blockchain

🗳 4. Cast Vote

Enter enrollment number

Live photo capture

Face encoding verified

Vote stored permanently on blockchain

📊 5. Live Results

Updates directly from Smart Contract

No manual manipulation possible

🛠 Tech Stack
Backend

Python Flask

OpenCV

face_recognition (dlib based)

NumPy

SQLAlchemy + MySQL

bcrypt

PyJWT

Web3.py

Frontend

HTML5

CSS

JavaScript

Webcam Based Face Detection

Blockchain

Solidity Smart Contract

Ethereum / Ganache / Hardhat / Infura

📂 Project Structure
project/
│
├── backend/
│   ├── app.py
│   ├── create_admin.py
│   ├── face_utils.py
│   ├── models.py
│   ├── managedelection.sol
│   ├── config/
│   │   └── secret.py
│   ├── uploads/
│   └── venv310/               # Python Virtual Environment
│
└── frontend/
    ├── index.html
    ├── admin_login.html
    ├── admin.html
    ├── voter.html
    ├── candidate.html
    ├── results.html
    └── style.css

⚙ Installation & Setup
1️⃣ Install Requirements

requirements.txt

Flask
Flask-Cors
opencv-python
numpy
face_recognition
dlib
SQLAlchemy
PyMySQL
bcrypt
PyJWT
web3
requests
urllib3
cmake


Install using:

pip install -r requirements.txt


Python 3.10 recommended (your venv = venv310)

2️⃣ Configure MySQL
CREATE DATABASE decentralised_voting;


Update credentials in:

backend/models.py  
backend/config/secret.py

3️⃣ Configure Blockchain (Very Important)

Edit secret.py

RPC_URL = "http://127.0.0.1:7545"
CONTRACT_ADDRESS = "0xYourContract"
ADMIN_PRIVATE_KEY = "your-private-key"
ADMIN_ACCOUNT = "0xAdminAddress"


Deploy managedelection.sol → paste contract address.

4️⃣ Run Server
cd backend
python app.py


Runs at → http://127.0.0.1:5000

👨‍💼 Create Admin (First Time Only)
python create_admin.py


Process:

Enter username

Enter password

Camera opens → capture face

Stored securely (embedding + hashed password)

🔐 Admin Login Flow

Open:

/admin


Enter username + password → camera starts → face verified → dashboard opens

🧑‍🎓 Register a Voter

Admin login required

Open /voter

Enter enrollment + name

Capture face

Voter saved (DB + blockchain hash)

🗳 Cast Vote

Open /

Enter enrollment

Capture live face

Select candidate

Vote stored on blockchain

📊 View Election Results

Visit:

/results


Shows candidates & votes live from smart contract.

🔍 Face Recognition Pipeline
Live Camera → Detect Face → Encode (128D vector) → Compare → Hash → Blockchain Vote


Security Core:

✔ No duplicate face allowed
✔ Cannot use image from gallery
✔ Hash hides identity
✔ Blockchain protects voting records

🛡 Security Highlights
Protection	Status
Duplicate vote prevention	✔
Face spoofing protection	✔
Admin 3-layer security	✔
Blockchain immutability	✔
No central manipulation	✔
📜 License

MIT License (modifiable for academic use)

👤 Author

Team :- Secure Chain 
members :-
1 saurabh kumar lodhi
2 Abhishek singh
3 Ankit chaurasiya
4 harsit garg
5 kajal sisodiya
Decentralized Voting System with Facial Authentication