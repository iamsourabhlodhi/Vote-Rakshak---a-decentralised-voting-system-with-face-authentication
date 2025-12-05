import cv2, os, bcrypt
from models import Admin, session
from face_utils import encode_face
import face_recognition

print("✅ DB Ready")
print("Enter new admin details\n")

username = input("Username: ").strip()
password = input("Password: ").strip()

# ---------------- Camera capture ----------------
print("\n📷 Starting camera. Press SPACE to capture, ESC to quit.")
cam = cv2.VideoCapture(0)

if not cam.isOpened():
    print("❌ Cannot open camera. Provide image path instead.")
    img_path = input("Enter image path (or 'exit'): ").strip()
    if img_path.lower() == "exit":
        exit()
    if not os.path.exists(img_path):
        print("❌ File not found. Exiting.")
        exit()
    capture_path = img_path
else:
    capture_path = None
    while True:
        ret, frame = cam.read()
        if not ret:
            print("❌ Camera read failed.")
            break

        try:
            cv2.imshow("Admin Capture - SPACE to capture, ESC to cancel", frame)
            key = cv2.waitKey(1) & 0xFF
        except Exception:
            # Headless mode → auto capture
            print("⚠ Preview not supported. Capturing automatically.")
            capture_path = "admin_temp.jpg"
            cv2.imwrite(capture_path, frame)
            break

        if key == 27:  # ESC
            print("Cancelled.")
            cam.release()
            try: cv2.destroyAllWindows()
            except: pass
            exit()

        if key == 32:  # SPACE
            capture_path = "admin_temp.jpg"
            cv2.imwrite(capture_path, frame)
            print("✔ Captured to admin_temp.jpg")
            break

    cam.release()
    try: cv2.destroyAllWindows()
    except: pass


# ---------------- Detect & Encode face ----------------
try:
    # Read image into numpy first (avoid later file-locks)
    img = cv2.imread(capture_path)
    if img is None:
        raise Exception("Captured image unreadable")

    # Quick detection using face_recognition
    locations = face_recognition.face_locations(img[:, :, ::-1], model="hog")
    if len(locations) == 0:
        print("❌ No face detected in provided image.")
        if capture_path == "admin_temp.jpg" and os.path.exists(capture_path):
            os.remove(capture_path)
        exit()

    print("✔ Face detected")

    enc = encode_face(img)   # pass numpy BGR image
    print("✔ Face encoded (128-D dlib encoding)")
except Exception as e:
    print("❌ Error:", e)
    if capture_path == "admin_temp.jpg" and os.path.exists(capture_path):
        os.remove(capture_path)
    exit()


# ---------------- Store admin in DB ----------------
try:
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    new_admin = Admin(
        username=username,
        password_hash=hashed,
        face_encoding=enc.tobytes()   # RAW BYTES
    )

    session.add(new_admin)
    session.commit()
except Exception as e:
    print("❌ DB error:", e)
    session.rollback()
    if capture_path == "admin_temp.jpg" and os.path.exists(capture_path):
        os.remove(capture_path)
    exit()


# ---------------- Cleanup ----------------
if capture_path == "admin_temp.jpg" and os.path.exists(capture_path):
    os.remove(capture_path)

print("\n🎉 ADMIN CREATED SUCCESSFULLY!")
print(" Username:", username)
print(" Face Encoding Stored ✔")
