

# ==========================================
# FILE: app.py
# ==========================================

from flask import (
    Flask, request, jsonify, render_template,
    redirect, Response, session
)
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from groq import Groq
import requests, os, smtplib, base64, time, random, uuid, datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pymysql
pymysql.install_as_MySQLdb()
import re
from collections import defaultdict

import google.generativeai as genai

import sys
sys.stdout.reconfigure(encoding="utf-8")




CHAT_MEMORY = defaultdict(lambda: {
    "language": None,
    "emotion": "neutral",
    "user_name": None,
    "greet_count": 0,
    "last_intent": None,
    "turns": 0
})
def decay_emotion(current):
    decay_map = {
        "sad": "neutral",
        "angry": "neutral",
        "happy": "neutral"
    }
    return decay_map.get(current, "neutral")






def clean_short_reply(text):
    fillers = ["or", "aur", "sunao", "bolo", "acha", "haan", "hmm", "ok"]
    return text in fillers or len(text.split()) <= 2

def detect_language(text):
    hinglish_words = ["kaise", "haan", "nahi", "kya", "sunao", "aur", "or"]
    for w in hinglish_words:
        if w in text:
            return "hinglish"
    return "english"


def detect_emotion(text):
    text = text.lower()
    if any(w in text for w in ["sad", "dukhi", "low", "tension", "akela", "yaad"]):
        return "sad"
    if any(w in text for w in ["happy", "khush", "mast", "badiya"]):
        return "happy"
    if any(w in text for w in ["gussa", "angry", "pareshan"]):
        return "angry"
    return "neutral"


# ================= LOAD ENV =================
load_dotenv()
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")


# ---------- GEMINI ----------
# ---------- GEMINI (PRIMARY) ----------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
gemini_client = None

import google.generativeai as genai

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
else:
    print("⚠️ GEMINI_API_KEY not found")



# ---------- GROQ ----------
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
groq_client = None
GROQ_MODEL = "llama-3.1-8b-instant"

if GROQ_API_KEY:
    groq_client = Groq(api_key=GROQ_API_KEY)
else:
    print("⚠️ GROQ_API_KEY not found")


ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")


MAIL_EMAIL = os.getenv("MAIL_EMAIL")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")

# ---------- GOOGLE OAUTH ----------
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://127.0.0.1:5000/google/callback")
SMTP_PORT = int(os.getenv("SMTP_PORT", 465))

if not GROQ_API_KEY:
    raise ValueError("❌ GROQ_API_KEY missing")

GOOGLE_REDIRECT_URI = "http://127.0.0.1:5000/google/callback"

# ================= FLASK APP =================
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = FLASK_SECRET_KEY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

CORS(app)


# ================= DATABASE =================
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"


app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(200))
    provider = db.Column(db.String(20))
    phone = db.Column(db.String(20))
    location = db.Column(db.String(100))
    avatar = db.Column(db.Text)

class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

with app.app_context():
    db.create_all()

# ================= AI SYSTEM PROMPT =================
SYSTEM_PROMPT = """You are SoftCare AI — a calm, emotionally intelligent human assistant.

Speak like a real person, not like an AI.
Replies should feel natural, short, and human.

Rules:
- Do NOT explain emotions, just respond naturally
- Do NOT lecture or give long advice unless asked
- Match user's language (Hinglish / English)
- If user is low → be gentle
- If casual → be casual
- If user says "aur / or / aage" → continue same topic
- Avoid repeating the same lines
- One soft emoji max 🙂
- Never start reply with emoji

Identity:
If asked who created you, reply exactly:
"I was created by Rahul Verma."
"""

def gemini_generate(prompt):
    model = genai.GenerativeModel("gemini-1.5-pro")
    response = model.generate_content(prompt)
    return response.text.strip()



def get_ai_reply(message, emotion="neutral", user_location=None):
    now = datetime.datetime.now()

    system_context = SYSTEM_PROMPT + f"""

CURRENT USER EMOTION: {emotion}
CURRENT TIME: {now.strftime("%I:%M %p")}
CURRENT DATE: {now.strftime("%A, %d %B %Y")}
USER LOCATION: {user_location or "Unknown"}

Respond naturally.
Match tone and language.
Do NOT mention emotion explicitly.

User: {message}
"""

    # ================= GEMINI (PRIMARY) =================
    if gemini_client:
        try:
            return gemini_generate(system_context)
        except Exception as e:
            print("⚠️ Gemini failed → switching to Groq")
            print(e)

    # ================= GROQ (FALLBACK) =================
    if groq_client:
        try:
            chat = groq_client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": message}
                ],
                temperature=0.8,
                max_tokens=300
            )
            return chat.choices[0].message.content.strip()
        except Exception as e:
            print("❌ Groq failed")
            print(e)

    # ================= FINAL SAFE =================
    return random.choice([
        "Thoda sa issue aa gaya hai 🙂 ek baar phir try karte hain.",
        "Network thoda slow lag raha hai 🙂",
        "Main yahin hoon 🙂 bas ek second do."
    ])


# ================= EMAIL =================
def send_welcome_email(to_email, user_name, provider):
    subject = "✨ Welcome to SoftCare AI — Your personal assistant"
    signup_method = "Google Sign-In" if provider == "google" else "Email & Password"

    html = f"""
    <html>
    <body style="background:#020617;color:#fff;font-family:Inter,Arial;padding:40px">
      <div style="max-width:600px;margin:auto;
        background:linear-gradient(180deg,rgba(255,255,255,.12),rgba(255,255,255,.04));
        border-radius:22px;padding:36px;
        box-shadow:0 30px 80px rgba(0,0,0,.8)">
        <h1 style="color:#c7b8ff">SoftCare AI</h1>
        <h2>Welcome, {user_name} 👋</h2>
        <p>Your account was created using <b>{signup_method}</b>.</p>
        <p>SoftCare AI is here to help you simplify your life.</p>
        <a href="http://127.0.0.1:5000/dashboard"
           style="display:inline-block;margin-top:24px;
           padding:14px 30px;border-radius:999px;
           background:linear-gradient(135deg,#7c4dff,#5b21ff);
           color:#fff;text-decoration:none;">
           Start Chatting
        </a>
        <p style="margin-top:30px;font-size:12px;color:#9ca3af">
          © 2025 SoftCare AI • Do not reply
        </p>
      </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["From"] = f"SoftCare AI <{MAIL_EMAIL}>"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(MAIL_EMAIL, MAIL_PASSWORD)
            server.sendmail(MAIL_EMAIL, to_email, msg.as_string())
        print("✅ Welcome email sent to", to_email)
    except Exception as e:
        print("❌ Email error:", e)

def send_reset_email(to_email, token):
    reset_link = f"http://127.0.0.1:5000/reset-password?token={token}"
    subject = "🔒 Reset your SoftCare AI Password"
    
    html = f"""
    <html>
    <body style="background:#020617;color:#fff;font-family:Inter,Arial;padding:40px">
      <div style="max-width:500px;margin:auto;
        background:#0f172a;border-radius:20px;padding:30px;
        border:1px solid #334155">
        <h2 style="color:#7c4dff;margin-top:0">Password Reset</h2>
        <p>You requested to reset your password. Click below to proceed:</p>
        <a href="{reset_link}"
           style="display:inline-block;margin:20px 0;padding:12px 24px;
           background:#7c4dff;color:#fff;text-decoration:none;border-radius:8px">
           Reset Password
        </a>
        <p style="color:#94a3b8;font-size:12px">Link expires in 15 minutes.</p>
        <p style="color:#94a3b8;font-size:12px">If you didn't ask for this, ignore this email.</p>
      </div>
    </body>
    </html>
    """
    
    msg = MIMEMultipart("alternative")
    msg["From"] = f"SoftCare AI <{MAIL_EMAIL}>"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(MAIL_EMAIL, MAIL_PASSWORD)
            server.sendmail(MAIL_EMAIL, to_email, msg.as_string())
        print("✅ Reset email sent to", to_email)
        return True
    except Exception as e:
        print("❌ Reset email error:", e)
        return False

# ================= ROUTES =================
@app.route("/me")
def me():
    if "user" not in session:
        return jsonify({"error": "not logged in"}), 401
    
    email = session["user"]["email"]
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "provider": user.provider,
        "phone": user.phone,
        "location": user.location,
        "avatar": user.avatar
    })

@app.route("/")
def landing():
    return render_template("index.html")

@app.route("/login-page")
def login_page():
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login-page")
    
    email = session["user"]["email"]
    user = User.query.filter_by(email=email).first()

    return render_template(
        "dashboard.html",
        user=user
    )

@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect("/login-page")

    email = session["user"]["email"]
    user = User.query.filter_by(email=email).first()

    return render_template(
        "profile.html",
        user=user
    )


@app.route("/update-profile", methods=["POST"])
def update_profile():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    email = session["user"]["email"]

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.phone = data.get("phone")
    user.location = data.get("location")

    # Handle Avatar Upload
    avatar_data = data.get("avatar")
    if avatar_data and "base64" in avatar_data:
        try:
            # Format: "data:image/png;base64,iVBORw0KGgo..."
            header, encoded = avatar_data.split(",", 1)
            file_ext = header.split(";")[0].split("/")[1] or "png"
            
            # Create uploads dir if not exists
            upload_folder = os.path.join(app.static_folder, "uploads")
            os.makedirs(upload_folder, exist_ok=True)
            
            # Generate filename
            filename = f"avatar_{user.id}_{int(time.time())}.{file_ext}"
            file_path = os.path.join(upload_folder, filename)
            
            # Decode and save
            with open(file_path, "wb") as f:
                f.write(base64.b64decode(encoded))
            
            # Save relative path to DB
            user.avatar = f"/static/uploads/{filename}"
        except Exception as e:
            print(f"Error saving avatar: {e}")
            # Continue without updating avatar if error

    db.session.commit()

    # session update (important to refresh session data)
    session["user"]["phone"] = user.phone
    session["user"]["location"] = user.location
    session["user"]["avatar"] = user.avatar

    return jsonify({"message": "Profile updated successfully"})

    
# ================= EMAIL SIGNUP =================
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json

    if User.query.filter_by(email=data.get("email")).first():
        return jsonify({"error": "Email already exists"}), 400

    user = User(
        name=data["name"],
        email=data["email"],
        password=generate_password_hash(data["password"]),
        provider="email"
    )
    db.session.add(user)
    db.session.commit()

    send_welcome_email(user.email, user.name, "email")

    return jsonify({"message": "Account created"})

# ================= EMAIL LOGIN =================
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = User.query.filter_by(email=data["email"]).first()

    if not user:
        return jsonify({"error": "Account not found"}), 401

    if user.provider != "email":
        return jsonify({
            "error": "This account uses Google Sign-In. Please continue with Google."
        }), 401

    if not check_password_hash(user.password, data["password"]):
        return jsonify({"error": "Invalid password"}), 401

    session["user"] = {
        "name": user.name,
        "email": user.email,
        "provider": user.provider
    }

    return jsonify({"redirect": "/dashboard"})

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login-page")

# ================= FORGOT PASSWORD =================
@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.json
    email = data.get("email")
    
    user = User.query.filter_by(email=email).first()
    if not user:
        # Security: Don't reveal if user exists
        return jsonify({"message": "If that email exists, we sent a reset link."})
        
    if user.provider != "email":
        return jsonify({"error": "This account uses Google Login."}), 400

    token = str(uuid.uuid4())
    reset_entry = PasswordReset(email=email, token=token)
    db.session.add(reset_entry)
    db.session.commit()
    
    send_reset_email(email, token)
    
    return jsonify({"message": "If that email exists, we sent a reset link."})

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "GET":
        token = request.args.get("token")
        entry = PasswordReset.query.filter_by(token=token).first()
        
        if not entry:
            return "Invalid or expired token", 400
            
        # Check expiry (15 mins)
        if (datetime.datetime.utcnow() - entry.created_at).total_seconds() > 900:
             return "Token expired", 400
             
        return render_template("reset_password.html", token=token)

    # POST (Update Password)
    data = request.json
    token = data.get("token")
    new_password = data.get("password")
    
    entry = PasswordReset.query.filter_by(token=token).first()
    if not entry:
        return jsonify({"error": "Invalid token"}), 400
        
    user = User.query.filter_by(email=entry.email).first()
    if user:
        user.password = generate_password_hash(new_password)
        db.session.delete(entry) # Consume token
        db.session.commit()
        return jsonify({"message": "Password updated successfully"})
    
    return jsonify({"error": "User not found"}), 400

# ================= GOOGLE LOGIN =================
@app.route("/google/login")
def google_login():
    url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?response_type=code&client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT_URI}"
        "&scope=openid%20email%20profile"
    )
    return redirect(url)

@app.route("/google/callback")
def google_callback():
    code = request.args.get("code")

    token = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": GOOGLE_REDIRECT_URI
        }
    ).json()

    access_token = token.get("access_token")
    if not access_token:
        return "Google login failed", 400

    user_info = requests.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        headers={"Authorization": f"Bearer {access_token}"}
    ).json()

    email = user_info["email"]
    name = user_info["name"]
    picture = user_info.get("picture")

    user = User.query.filter_by(email=email).first()

    # 🚫 CASE 1: Email exists but provider = email
    if user and user.provider == "email":
        return (
            "This email is already registered using Email & Password. "
            "Please login using email & password.",
            400
        )

    # ✅ CASE 2: First time Google signup
    if not user:
        user = User(
            name=name,
            email=email,
            provider="google"
        )
        db.session.add(user)
        db.session.commit()
        send_welcome_email(email, name, "google")

    # ✅ Login session
    session["user"] = {
        "name": user.name,
        "email": user.email,
        "provider": user.provider,
        "picture": picture
    }

    return redirect("/dashboard")


# ================= ADMIN PANEL =================
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/admin/dashboard")
        
        return render_template("admin_login.html", error="Invalid credentials")

    return render_template("admin_login.html")

@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin"):
        return redirect("/admin/login")
    
    users = User.query.all()
    return render_template("admin_dashboard.html", users=users)

@app.route("/admin/delete/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if not session.get("admin"):
        return redirect("/admin/login")
    
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
    
    return redirect("/admin/dashboard")

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect("/admin/login")
@app.route("/stream", methods=["POST"])
def stream():
    raw_msg = request.json.get("message", "").strip()
    if not raw_msg:
        return Response("", mimetype="text/plain")

    # ---------- SESSION ----------
    sid = session.get("sid")
    if not sid:
        sid = session["sid"] = str(uuid.uuid4())

    mem = CHAT_MEMORY[sid]
    mem["turns"] += 1

    msg = raw_msg.lower().strip()

    # ---------- LANGUAGE LOCK ----------
    if not mem["language"] and len(msg.split()) > 2:
        mem["language"] = detect_language(msg)

    # ---------- NAME CAPTURE (STRICT) ----------
    name_match = re.search(
        r"\b(my name is|mera naam|mera name)\s+([a-zA-Z]{3,})\b",
        raw_msg,
        re.IGNORECASE
    )

    if name_match:
        mem["user_name"] = name_match.group(2).capitalize()
        return Response(
            f"Theek hai, {mem['user_name']}."
            if mem["language"] == "hinglish"
            else f"Alright, {mem['user_name']}.",
            mimetype="text/plain"
        )

    # ---------- NAME QUERY ----------
    if any(p in msg for p in [
        "mera naam kya",
        "mera name kya",
        "mera name batao",
        "what is my name",
        "who am i"
    ]):
        if mem["user_name"]:
            return Response(
                f"Tumhara naam {mem['user_name']} hai."
                if mem["language"] == "hinglish"
                else f"Your name is {mem['user_name']}.",
                mimetype="text/plain"
            )
        else:
            return Response(
                "Tumne abhi apna naam bataya nahi."
                if mem["language"] == "hinglish"
                else "You haven’t told me your name yet.",
                mimetype="text/plain"
            )

    # ---------- GREETINGS (EMOJI ONLY HERE) ----------
    if msg in ["hi", "hello", "hey", "hii"]:
        mem["greet_count"] += 1
        if mem["greet_count"] == 1:
            return Response("Hey 🙂", mimetype="text/plain")
        return Response("Haan 🙂", mimetype="text/plain")

    # ---------- SMALL TALK ----------
    if msg in ["kaise ho", "kya haal", "how are you"]:
        return Response(
            "Theek hoon."
            if mem["language"] == "hinglish"
            else "I’m doing well.",
            mimetype="text/plain"
        )

    if msg in ["aur batao", "or batao", "what's up"]:
        return Response(
            "Bas normal chal raha hai."
            if mem["language"] == "hinglish"
            else "Nothing much, just the usual.",
            mimetype="text/plain"
        )

    # ---------- BYE ----------
    if msg in ["bye", "thanks", "thank you", "ok bye"]:
        return Response("🙂", mimetype="text/plain")

    # ---------- DEFAULT (AI MODEL) ----------
    user_location = session.get("user", {}).get("location")
    reply = get_ai_reply(raw_msg, mem["emotion"], user_location)

    def generate():
        for ch in reply:
            yield ch
            time.sleep(0.008)

    return Response(generate(), mimetype="text/plain")



# ================= RUN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)


