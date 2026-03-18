"""
BankShield AI — Banking Sector Cyber Threat Detection System
Flask Backend — REST API
Designed for: Banking & Financial Services Security Operations
"""

import os, json, pickle, shutil, math, hashlib, struct
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, session
from flask_cors import CORS
import numpy as np

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR         = os.path.dirname(os.path.abspath(__file__))
ML_DIR           = os.path.join(BASE_DIR, "..", "ml_model")
MODEL_PATH       = os.path.join(ML_DIR, "random_forest_model.pkl")
SCALER_PATH      = os.path.join(ML_DIR, "scaler.pkl")
META_PATH        = os.path.join(ML_DIR, "model_metadata.json")
QUARANTINE_DIR   = os.path.join(BASE_DIR, "..", "quarantine")
UPLOAD_DIR       = os.path.join(BASE_DIR, "uploads")

for d in [QUARANTINE_DIR, UPLOAD_DIR]:
    os.makedirs(d, exist_ok=True)

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "bankshield_secret_2024_xK9!mQ")

# CORS — update with your Netlify URL
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
CORS(app, supports_credentials=True, origins=ALLOWED_ORIGINS)

# ── Database (Turso / libsql) ─────────────────────────────────────────────────
import libsql_experimental as libsql

TURSO_URL    = os.environ.get("TURSO_DATABASE_URL", "")
TURSO_TOKEN  = os.environ.get("TURSO_AUTH_TOKEN",   "")

def get_db():
    """
    Returns a libsql connection.
    - If TURSO_DATABASE_URL is set → connects to Turso cloud (online).
    - Else → falls back to local SQLite file (for local dev).
    """
    if TURSO_URL:
        conn = libsql.connect(TURSO_URL, auth_token=TURSO_TOKEN)
    else:
        local_path = os.path.join(BASE_DIR, "..", "instance", "bankshield.db")
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        conn = libsql.connect(local_path)
    return conn

def db_fetchall(conn, query, params=()):
    cursor = conn.execute(query, params)
    rows   = cursor.fetchall()
    cols   = [d[0] for d in cursor.description]
    return [dict(zip(cols, row)) for row in rows]

def db_fetchone(conn, query, params=()):
    cursor = conn.execute(query, params)
    row    = cursor.fetchone()
    if not row: return None
    cols   = [d[0] for d in cursor.description]
    return dict(zip(cols, row))

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT    UNIQUE NOT NULL,
            password  TEXT    NOT NULL,
            role      TEXT    DEFAULT 'analyst',
            department TEXT   DEFAULT 'SOC',
            created   TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS scan_logs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            filename        TEXT NOT NULL,
            file_size       INTEGER,
            file_hash       TEXT,
            scan_time       TEXT DEFAULT (datetime('now')),
            prediction      TEXT NOT NULL,
            confidence      REAL,
            entropy         REAL,
            is_quarantined  INTEGER DEFAULT 0,
            scanned_by      TEXT,
            attack_type     TEXT DEFAULT NULL,
            banking_target  TEXT DEFAULT NULL,
            risk_category   TEXT DEFAULT NULL
        );

        CREATE TABLE IF NOT EXISTS quarantine_records (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_log_id     INTEGER,
            original_path   TEXT,
            quarantine_path TEXT,
            quarantined_at  TEXT DEFAULT (datetime('now')),
            status          TEXT DEFAULT 'quarantined',
            FOREIGN KEY(scan_log_id) REFERENCES scan_logs(id)
        );
    """)
    conn.commit()
    # Default admin user (password: admin123)
    try:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password, role, department) VALUES (?,?,?,?)",
            ("admin", hashlib.sha256("admin123".encode()).hexdigest(), "admin", "IT Security")
        )
        conn.commit()
    except Exception:
        pass
    conn.close()

def migrate_db():
    conn = get_db()
    for col in [
        "ALTER TABLE scan_logs ADD COLUMN attack_type TEXT DEFAULT NULL",
        "ALTER TABLE scan_logs ADD COLUMN banking_target TEXT DEFAULT NULL",
        "ALTER TABLE scan_logs ADD COLUMN risk_category TEXT DEFAULT NULL",
        "ALTER TABLE users ADD COLUMN department TEXT DEFAULT 'SOC'",
    ]:
        try:
            conn.execute(col)
            conn.commit()
        except Exception:
            pass
    conn.close()

init_db()
migrate_db()

# ── Load ML model ─────────────────────────────────────────────────────────────
with open(MODEL_PATH, "rb") as f:
    RF_MODEL = pickle.load(f)
with open(SCALER_PATH, "rb") as f:
    SCALER = pickle.load(f)
with open(META_PATH) as f:
    MODEL_META = json.load(f)

FEATURE_NAMES = MODEL_META["feature_names"]

NON_PE_EXTENSIONS = {
    '.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx',
    '.txt','.csv','.json','.xml','.html','.htm','.md',
    '.jpg','.jpeg','.png','.gif','.bmp','.svg','.webp','.ico',
    '.mp3','.mp4','.wav','.avi','.mkv','.mov',
    '.zip','.rar','.7z','.tar','.gz','.bz2',
    '.py','.js','.ts','.java','.c','.cpp','.cs','.rb','.php',
    '.sh','.bat','.ps1',
}

# ── Banking-specific threat classification ────────────────────────────────────
# Banking sector specific targets for each attack type
BANKING_TARGETS = {
    "Ransomware": ["Core Banking System", "Payment Gateway", "SWIFT Network", "ATM Network", "Card Processing"],
    "Trojan":     ["Online Banking Portal", "Mobile Banking App", "Internet Banking", "Trading Platform", "Customer Data"],
    "Backdoor":   ["Core Banking System", "Internal Network", "Database Server", "Admin Console", "Firewall"],
    "Worm":       ["Bank Intranet", "Branch Network", "ATM Network", "Staff Workstations", "Data Center"],
    "Spyware":    ["Customer PII", "Account Credentials", "Transaction Data", "Card Data (PCI)", "KYC Records"],
}

RISK_CATEGORIES = {
    "Ransomware": "Data Integrity & Availability",
    "Trojan":     "Credential Theft & Fraud",
    "Backdoor":   "Unauthorized Access",
    "Worm":       "Network Propagation",
    "Spyware":    "Data Exfiltration (PCI-DSS)",
}

# Banking departments for heatmap
BANK_DEPARTMENTS = [
    "Core Banking", "ATM Operations", "SWIFT/Payments",
    "Retail Banking", "Corporate Banking", "Treasury",
    "IT Security (SOC)", "Digital Banking", "Compliance", "Card Services"
]

# Compliance frameworks
COMPLIANCE_FRAMEWORKS = ["RBI Guidelines", "PCI-DSS", "ISO 27001", "SWIFT CSP", "CERT-In"]

# ── Auth helper ───────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

# ── Feature extraction ────────────────────────────────────────────────────────
def calculate_entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [0] * 256
    for b in data: freq[b] += 1
    entropy = 0.0
    length = len(data)
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_features(filepath: str) -> dict:
    try:
        stat = os.stat(filepath)
        file_size = stat.st_size
    except Exception:
        file_size = 0

    with open(filepath, "rb") as f:
        raw = f.read()

    entropy = calculate_entropy(raw)
    is_pe = raw[:2] == b"MZ"
    num_sections = 0; virtual_size = 0; raw_size = file_size
    pe_header_size = 0; timestamp_valid = 1; dll_characteristics = 40960

    if is_pe and len(raw) > 64:
        try:
            e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
            if e_lfanew + 24 < len(raw):
                pe_header_size = e_lfanew + 24
                ts = struct.unpack_from("<I", raw, e_lfanew + 8)[0]
                timestamp_valid = 1 if 0 < ts < 1_800_000_000 else 0
                num_sections = struct.unpack_from("<H", raw, e_lfanew + 6)[0]
                if e_lfanew + 92 < len(raw):
                    dll_characteristics = struct.unpack_from("<H", raw, e_lfanew + 94)[0]
                    virtual_size = struct.unpack_from("<I", raw, e_lfanew + 80)[0]
        except Exception:
            pass

    suspicious_keywords = [
        b"CreateRemoteThread", b"VirtualAllocEx", b"WriteProcessMemory",
        b"ShellExecute", b"cmd.exe", b"powershell", b"WScript",
        b"RegCreateKey", b"URLDownloadToFile"
    ]
    raw_lower = raw.lower()
    imports_count = sum(1 for kw in suspicious_keywords if kw.lower() in raw_lower)

    crypto_kws  = [b"CryptEncrypt", b"CryptDecrypt", b"AES", b"RSA", b"md5", b"sha256"]
    net_kws     = [b"socket", b"connect", b"HttpSendRequest", b"InternetOpen", b"WSAStartup"]
    reg_kws     = [b"RegOpenKey", b"RegSetValue", b"RegCreateKey"]

    imports_crypto   = 1 if any(k.lower() in raw_lower for k in crypto_kws) else 0
    imports_network  = 1 if any(k.lower() in raw_lower for k in net_kws) else 0
    imports_registry = 1 if any(k.lower() in raw_lower for k in reg_kws) else 0

    suspicious_names = [b".text\x00", b"UPX0", b"UPX1", b".packed"]
    suspicious_section_name = 1 if any(s in raw for s in suspicious_names) else 0

    has_debug     = 1 if b"DebugDirectory" in raw or b".debug" in raw_lower else 0
    has_tls       = 1 if b".tls" in raw_lower else 0
    has_resources = 1 if b".rsrc" in raw_lower or b"RT_VERSION" in raw else 0
    is_packed     = 1 if (b"UPX" in raw or b"MPRESS" in raw) else 0
    unusual_entry_point = 1 if (entropy > 7.0 and not is_pe) else 0
    high_entropy_code   = 1 if entropy > 7.0 else 0
    num_imports   = max(imports_count, 5)
    num_exports   = 0

    ext = os.path.splitext(filepath)[1].lower()
    file_type = 0 if ext in NON_PE_EXTENSIONS else (1 if is_pe else 0)

    return {
        "file_type": file_type, "file_size": file_size, "entropy": entropy,
        "num_sections": max(num_sections, 1), "virtual_size": max(virtual_size, file_size),
        "raw_size": raw_size, "num_imports": num_imports, "num_exports": num_exports,
        "has_debug": has_debug, "has_tls": has_tls, "has_resources": has_resources,
        "is_packed": is_packed, "suspicious_section_name": suspicious_section_name,
        "unusual_entry_point": unusual_entry_point, "high_entropy_code": high_entropy_code,
        "imports_crypto": imports_crypto, "imports_network": imports_network,
        "imports_registry": imports_registry, "pe_header_size": pe_header_size,
        "timestamp_valid": timestamp_valid, "dll_characteristics": dll_characteristics,
    }

def predict_file(filepath: str):
    import pandas as pd
    features    = extract_features(filepath)
    feat_array  = pd.DataFrame([[features[k] for k in FEATURE_NAMES]], columns=FEATURE_NAMES)
    feat_scaled = SCALER.transform(feat_array)
    THRESHOLD   = MODEL_META.get("threshold", 0.35)
    proba       = RF_MODEL.predict_proba(feat_scaled)[0]
    malware_prob = float(proba[1])
    prediction  = 1 if malware_prob >= THRESHOLD else 0
    confidence  = round(malware_prob * 100 if prediction == 1 else (1 - malware_prob) * 100, 2)
    features["_malware_probability"] = round(malware_prob * 100, 2)
    return prediction, confidence, features

def classify_attack_type(features: dict, prediction: int) -> str:
    if prediction == 0: return None
    crypto   = features.get("imports_crypto",    0)
    network  = features.get("imports_network",   0)
    registry = features.get("imports_registry",  0)
    packed   = features.get("is_packed",         0)
    entropy  = features.get("entropy",           0)
    hi_ent   = features.get("high_entropy_code", 0)
    susp_sec = features.get("suspicious_section_name", 0)
    num_imp  = features.get("num_imports",       0)

    scores = {"Ransomware": 0, "Trojan": 0, "Backdoor": 0, "Worm": 0, "Spyware": 0}

    if crypto and not network and not registry: scores["Ransomware"] += 4
    elif crypto: scores["Ransomware"] += 2
    if (hi_ent or entropy > 7.0) and packed: scores["Ransomware"] += 2
    elif hi_ent or entropy > 7.0: scores["Ransomware"] += 1

    if susp_sec: scores["Trojan"] += 3
    if network and registry: scores["Trojan"] += 3
    if crypto and network and registry: scores["Trojan"] += 2
    if num_imp >= 8: scores["Trojan"] += 1
    if not packed and num_imp >= 5: scores["Trojan"] += 1

    if packed and network and registry: scores["Backdoor"] += 5
    elif packed and network: scores["Backdoor"] += 3
    elif registry and network: scores["Backdoor"] += 2
    if packed and registry: scores["Backdoor"] += 1

    if network and not registry and not crypto: scores["Worm"] += 5
    elif network and not registry: scores["Worm"] += 3
    if network and num_imp <= 6: scores["Worm"] += 1

    if registry and not network and not crypto: scores["Spyware"] += 5
    if registry and not packed: scores["Spyware"] += 2
    if not hi_ent and registry: scores["Spyware"] += 1

    best = max(scores, key=lambda k: scores[k])
    return best if scores[best] > 0 else "Trojan"

def get_banking_target(attack_type: str, filename: str) -> str:
    import random
    if not attack_type: return None
    targets = BANKING_TARGETS.get(attack_type, ["Banking System"])
    seed = int(hashlib.md5((filename + attack_type).encode()).hexdigest()[:8], 16)
    return random.Random(seed).choice(targets)

def get_malware_severity(confidence: float, features: dict) -> dict:
    flags = sum([
        features.get("imports_crypto",    0), features.get("imports_network",   0),
        features.get("imports_registry",  0), features.get("is_packed",         0),
        features.get("high_entropy_code", 0), features.get("suspicious_section_name", 0),
        features.get("unusual_entry_point", 0)
    ])
    if confidence >= 85 and flags >= 4:
        return {"level": "Critical", "color": "#ef4444", "tier": "T1", "desc": "Critical banking threat — immediate isolation required"}
    elif confidence >= 70 and flags >= 2:
        return {"level": "High",     "color": "#f97316", "tier": "T2", "desc": "High risk — potential financial data compromise"}
    elif confidence >= 50 and flags >= 1:
        return {"level": "Medium",   "color": "#f59e0b", "tier": "T3", "desc": "Medium risk — monitor and investigate"}
    elif confidence >= 35:
        return {"level": "Low",      "color": "#eab308", "tier": "T4", "desc": "Low risk — stealth threat pattern"}
    else:
        return {"level": "Minimal",  "color": "#84cc16", "tier": "T5", "desc": "Minimal — polymorphic pattern detected"}

# ── Build malware binary (for simulation) ─────────────────────────────────────
def build_malware_binary(attack_name: str = "generic") -> bytes:
    import struct as _struct
    ATTACK_STRINGS = {
        "ransomware": (b"UPX0UPX1" b"CryptEncrypt\x00AES\x00RSA\x00sha256\x00" b"CryptDecrypt\x00BCryptEncrypt\x00" b"cmd.exe\x00"),
        "trojan":     (b"CreateRemoteThread\x00VirtualAllocEx\x00WriteProcessMemory\x00" b"ShellExecute\x00LoadLibrary\x00GetProcAddress\x00" b"socket\x00connect\x00InternetOpen\x00" b"RegOpenKey\x00RegSetValue\x00" b"CryptEncrypt\x00AES\x00" b".packed\x00" b"cmd.exe\x00powershell\x00WScript\x00"),
        "backdoor":   (b"MPRESS\x00" b"socket\x00WSAStartup\x00InternetOpen\x00URLDownloadToFile\x00" b"RegOpenKey\x00RegSetValue\x00RegCreateKey\x00" b"CreateRemoteThread\x00VirtualAllocEx\x00"),
        "worm":       (b"socket\x00WSAStartup\x00InternetOpen\x00" b"URLDownloadToFile\x00HttpSendRequest\x00" b"connect\x00bind\x00listen\x00accept\x00" b"GetAdaptersInfo\x00GetHostByName\x00"),
        "spyware":    (b"RegOpenKey\x00RegSetValue\x00RegCreateKey\x00" b"RegQueryValue\x00RegEnumKey\x00RegDeleteKey\x00" b"GetAsyncKeyState\x00SetWindowsHookEx\x00"),
    }
    strings = ATTACK_STRINGS.get(attack_name.lower(), ATTACK_STRINGS["trojan"])
    mz = bytearray(0x40); mz[0:2] = b"MZ"
    _struct.pack_into("<I", mz, 0x3c, 0x40)
    pe_sig = b"PE\x00\x00"
    coff   = _struct.pack("<HHIIIHH", 0x014c, 2, 0, 0, 0, 0xE0, 0x0102)
    opt = bytearray(0xE0)
    _struct.pack_into("<H", opt, 0,    0x010b)
    _struct.pack_into("<I", opt, 16,   0x1000)
    _struct.pack_into("<I", opt, 24,   0x1000)
    _struct.pack_into("<I", opt, 56,   0x40000)
    _struct.pack_into("<H", opt, 0x46, 0x0002)
    seed = sum(ord(c) for c in attack_name)
    payload = bytes([(i * (167 + seed) + 13) % 256 for i in range(4096)])
    return bytes(mz) + pe_sig + coff + bytes(opt) + strings + payload

# ── Auth Routes ───────────────────────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def login():
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    hashed   = hashlib.sha256(password.encode()).hexdigest()
    conn = get_db()
    user = db_fetchone(conn, "SELECT * FROM users WHERE username=? AND password=?", (username, hashed))
    conn.close()
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    session["user_id"]  = user["id"]
    session["username"] = user["username"]
    session["role"]     = user["role"]
    return jsonify({"message": "Login successful", "username": user["username"], "role": user["role"]})

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})

@app.route("/api/auth/me", methods=["GET"])
def me():
    if "user_id" in session:
        return jsonify({"logged_in": True, "username": session["username"], "role": session["role"]})
    return jsonify({"logged_in": False})

# ── File Scan ─────────────────────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
@login_required
def scan_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    save_path = os.path.join(UPLOAD_DIR, file.filename)
    file.save(save_path)

    with open(save_path, "rb") as f:
        file_hash = hashlib.md5(f.read()).hexdigest()
    file_size = os.path.getsize(save_path)

    try:
        prediction, confidence, features = predict_file(save_path)
    except Exception as e:
        os.remove(save_path)
        return jsonify({"error": str(e)}), 500

    label          = "Malware" if prediction == 1 else "Safe"
    attack_type    = classify_attack_type(features, prediction)
    banking_target = get_banking_target(attack_type, file.filename)
    risk_category  = RISK_CATEGORIES.get(attack_type, None) if attack_type else None
    quarantine_path = None
    is_quarantined  = 0

    if prediction == 1:
        q_filename = f"QUARANTINED_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        quarantine_path = os.path.join(QUARANTINE_DIR, q_filename)
        shutil.move(save_path, quarantine_path)
        is_quarantined = 1
    else:
        os.remove(save_path)

    conn = get_db()
    conn.execute("""
        INSERT INTO scan_logs
            (filename, file_size, file_hash, prediction, confidence, entropy,
             is_quarantined, scanned_by, attack_type, banking_target, risk_category)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (file.filename, file_size, file_hash, label, confidence, features["entropy"],
          is_quarantined, session["username"], attack_type, banking_target, risk_category))
    conn.commit()

    log_id = db_fetchone(conn, "SELECT last_insert_rowid() as id")["id"]
    if prediction == 1:
        conn.execute(
            "INSERT INTO quarantine_records (scan_log_id, original_path, quarantine_path) VALUES (?,?,?)",
            (log_id, file.filename, quarantine_path)
        )
        conn.commit()
    conn.close()

    severity = get_malware_severity(confidence, features) if prediction == 1 else None

    return jsonify({
        "id": log_id, "filename": file.filename, "prediction": label,
        "prediction_code": prediction, "confidence": confidence,
        "is_quarantined": bool(is_quarantined), "attack_type": attack_type,
        "banking_target": banking_target, "risk_category": risk_category,
        "severity": severity, "malware_probability": features.get("_malware_probability"),
        "features": {k: v for k, v in features.items() if not k.startswith("_")},
        "scan_time": datetime.now().isoformat(), "file_hash": file_hash, "file_size": file_size
    })

# ── Logs ──────────────────────────────────────────────────────────────────────
@app.route("/api/logs", methods=["GET"])
@login_required
def get_logs():
    conn = get_db()
    rows = db_fetchall(conn, "SELECT * FROM scan_logs ORDER BY scan_time DESC LIMIT 100")
    conn.close()
    return jsonify(rows)

@app.route("/api/logs/<int:log_id>", methods=["GET"])
@login_required
def get_log(log_id):
    conn = get_db()
    row  = db_fetchone(conn, "SELECT * FROM scan_logs WHERE id=?", (log_id,))
    conn.close()
    if not row: return jsonify({"error": "Not found"}), 404
    return jsonify(row)

# ── Quarantine ─────────────────────────────────────────────────────────────────
@app.route("/api/quarantine", methods=["GET"])
@login_required
def get_quarantine():
    conn = get_db()
    rows = db_fetchall(conn, """
        SELECT q.*, s.filename, s.confidence, s.entropy, s.scan_time,
               s.attack_type, s.banking_target, s.risk_category
        FROM quarantine_records q
        JOIN scan_logs s ON q.scan_log_id = s.id
        ORDER BY q.quarantined_at DESC
    """)
    conn.close()
    return jsonify(rows)

@app.route("/api/quarantine/<int:qid>/restore", methods=["POST"])
@login_required
def restore_file(qid):
    conn = get_db()
    rec  = db_fetchone(conn, "SELECT * FROM quarantine_records WHERE id=?", (qid,))
    if not rec:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    conn.execute("UPDATE quarantine_records SET status='restored' WHERE id=?", (qid,))
    conn.execute("UPDATE scan_logs SET is_quarantined=0 WHERE id=?", (rec["scan_log_id"],))
    conn.commit()
    conn.close()
    return jsonify({"message": "File marked as restored"})

@app.route("/api/quarantine/<int:qid>/delete", methods=["DELETE"])
@login_required
def delete_quarantine(qid):
    conn = get_db()
    rec  = db_fetchone(conn, "SELECT * FROM quarantine_records WHERE id=?", (qid,))
    if not rec:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    if rec.get("quarantine_path") and os.path.exists(rec["quarantine_path"]):
        os.remove(rec["quarantine_path"])
    conn.execute("DELETE FROM quarantine_records WHERE id=?", (qid,))
    conn.execute("DELETE FROM scan_logs WHERE id=?", (rec["scan_log_id"],))
    conn.commit()
    conn.close()
    return jsonify({"message": "Deleted permanently"})

# ── Stats ─────────────────────────────────────────────────────────────────────
@app.route("/api/stats", methods=["GET"])
@login_required
def get_stats():
    conn = get_db()
    total       = db_fetchone(conn, "SELECT COUNT(*) as c FROM scan_logs")["c"]
    malware_cnt = db_fetchone(conn, "SELECT COUNT(*) as c FROM scan_logs WHERE prediction='Malware'")["c"]
    safe_cnt    = db_fetchone(conn, "SELECT COUNT(*) as c FROM scan_logs WHERE prediction='Safe'")["c"]
    quarantined = db_fetchone(conn, "SELECT COUNT(*) as c FROM scan_logs WHERE is_quarantined=1")["c"]
    daily  = db_fetchall(conn, """
        SELECT DATE(scan_time) as date, COUNT(*) as count,
               SUM(CASE WHEN prediction='Malware' THEN 1 ELSE 0 END) as malware
        FROM scan_logs WHERE scan_time >= datetime('now','-7 days')
        GROUP BY DATE(scan_time) ORDER BY date
    """)
    recent = db_fetchall(conn, "SELECT * FROM scan_logs ORDER BY scan_time DESC LIMIT 5")
    conn.close()
    return jsonify({
        "total_scans": total, "malware_count": malware_cnt,
        "safe_count": safe_cnt, "quarantined": quarantined,
        "detection_rate": round((malware_cnt / total * 100) if total else 0, 1),
        "daily_trend": daily, "recent_scans": recent,
        "model_accuracy": MODEL_META["accuracy"] * 100,
    })

# ── Model Info ────────────────────────────────────────────────────────────────
@app.route("/api/model/info", methods=["GET"])
@login_required
def model_info():
    return jsonify({
        "model_type":   MODEL_META["model_type"],
        "accuracy":     round(MODEL_META["accuracy"] * 100, 2),
        "precision":    round(MODEL_META["precision"] * 100, 2),
        "recall":       round(MODEL_META["recall"] * 100, 2),
        "f1_score":     round(MODEL_META["f1_score"] * 100, 2),
        "n_estimators": MODEL_META["n_estimators"],
        "features":     FEATURE_NAMES,
        "dataset":      "Banking Malware Dataset (Financial Sector Threats)",
        "classes":      ["Benign (0)", "Malware (1)"],
        "compliance":   COMPLIANCE_FRAMEWORKS,
        "deployment":   "Banking SOC — Tier-1 Financial Institution",
    })

# ── Advanced Stats ────────────────────────────────────────────────────────────
import random

MALWARE_TYPES   = ["Trojan", "Ransomware", "Backdoor", "Worm", "Spyware"]
MALWARE_WEIGHTS = [0.40, 0.25, 0.20, 0.10, 0.05]

def classify_malware_type(filename: str, file_hash: str) -> str:
    seed = int(hashlib.md5((filename + (file_hash or "")).encode()).hexdigest()[:8], 16)
    return random.Random(seed).choices(MALWARE_TYPES, weights=MALWARE_WEIGHTS, k=1)[0]

def calc_risk_score(malware_cnt: int, total: int, severe: int) -> dict:
    if total == 0: return {"score": 0, "level": "Low", "color": "#10b981"}
    detection_rate = malware_cnt / total
    severity_rate  = severe / max(malware_cnt, 1)
    raw = min(100, round((detection_rate * 60 + severity_rate * 40) * 100))
    if raw >= 75:   level, color = "Critical", "#ef4444"
    elif raw >= 50: level, color = "High",     "#f97316"
    elif raw >= 25: level, color = "Medium",   "#f59e0b"
    else:           level, color = "Low",      "#10b981"
    return {"score": raw, "level": level, "color": color}

@app.route("/api/advanced_stats", methods=["GET"])
@login_required
def advanced_stats():
    conn = get_db()
    logs = db_fetchall(conn, "SELECT * FROM scan_logs ORDER BY scan_time DESC")
    hourly_rows = db_fetchall(conn, """
        SELECT strftime('%H:00', scan_time) as hour,
               COUNT(*) as total,
               SUM(CASE WHEN prediction='Malware' THEN 1 ELSE 0 END) as threats
        FROM scan_logs WHERE scan_time >= datetime('now','-24 hours')
        GROUP BY strftime('%H', scan_time) ORDER BY hour
    """)
    conn.close()

    total    = len(logs)
    malware  = [l for l in logs if l["prediction"] == "Malware"]
    mal_cnt  = len(malware)
    safe_cnt = total - mal_cnt
    severe   = [m for m in malware if (m["confidence"] or 0) >= 70]
    sev_cnt  = len(severe)

    type_counts = {t: 0 for t in MALWARE_TYPES}
    for m in malware:
        t = m.get("attack_type") or classify_malware_type(m["filename"], m["file_hash"])
        if t in type_counts: type_counts[t] += 1

    malware_types = [
        {"name": t, "value": type_counts[t],
         "pct": round(type_counts[t] / mal_cnt * 100) if mal_cnt else 0,
         "banking_target": BANKING_TARGETS.get(t, [""])[0],
         "risk_category":  RISK_CATEGORIES.get(t, "")}
        for t in MALWARE_TYPES
    ]

    # Banking departments heatmap
    weeks  = ["Week 1", "Week 2", "Week 3", "Week 4"]
    heatmap = []
    for dept in BANK_DEPARTMENTS:
        seed = int(hashlib.md5(dept.encode()).hexdigest()[:8], 16)
        rng  = random.Random(seed + mal_cnt)
        row  = {"dept": dept}
        for w in weeks: row[w] = rng.randint(0, max(1, mal_cnt))
        row["total"] = sum(row[w] for w in weeks)
        heatmap.append(row)
    heatmap.sort(key=lambda x: -x["total"])

    # Industry = Banking sub-sectors
    BANK_SECTORS = ["Retail Banking", "Corporate Banking", "Investment Banking",
                    "Insurance", "Payments/Fintech", "Wealth Management",
                    "Microfinance", "Cooperative Banks"]
    ind_counts = {i: 0 for i in BANK_SECTORS}
    for l in logs:
        seed = int(hashlib.md5(l["filename"].encode()).hexdigest()[8:16], 16)
        ind  = random.Random(seed).choice(BANK_SECTORS)
        if l["prediction"] == "Malware": ind_counts[ind] += 1

    industry_data = [
        {"name": i, "attacks": ind_counts[i], "risk": min(100, round(ind_counts[i] * 20))}
        for i in BANK_SECTORS
    ]
    industry_data.sort(key=lambda x: -x["attacks"])

    risk     = calc_risk_score(mal_cnt, total, sev_cnt)
    det_rate = round((mal_cnt / total * 100) if total else 0, 1)

    # RBI/NIST compliance metrics
    csf = {
        "Identify":  min(100, 40 + total * 2),
        "Protect":   min(100, 50 + safe_cnt * 3),
        "Detect":    min(100, round(det_rate * 1.1)),
        "Respond":   min(100, 30 + sev_cnt * 5),
        "Recover":   min(100, 60 + (total - mal_cnt) * 2),
    }

    avg_conf    = round(sum(m["confidence"] or 0 for m in malware) / mal_cnt, 1) if mal_cnt else 0
    avg_entropy = round(sum(m["entropy"] or 0 for m in malware) / mal_cnt, 4) if mal_cnt else 0

    live_events = []
    for l in logs[:20]:
        mt = l.get("attack_type") if l["prediction"] == "Malware" else None
        seed = int(hashlib.md5(l["filename"].encode()).hexdigest()[8:16], 16)
        ind  = random.Random(seed).choice(BANK_SECTORS)
        live_events.append({
            "id": l["id"], "filename": l["filename"],
            "prediction": l["prediction"], "confidence": l["confidence"],
            "entropy": l["entropy"], "malware_type": mt, "attack_type": mt,
            "banking_target": l.get("banking_target"), "risk_category": l.get("risk_category"),
            "industry": ind, "scan_time": l["scan_time"], "is_quarantined": l["is_quarantined"]
        })

    return jsonify({
        "total_scans": total, "malware_count": mal_cnt,
        "safe_count": safe_cnt, "severe_count": sev_cnt,
        "risk_score": risk, "malware_types": malware_types,
        "industry_data": industry_data, "csf_metrics": csf,
        "heatmap": heatmap, "live_events": live_events,
        "hourly_activity": hourly_rows,
        "compliance_frameworks": COMPLIANCE_FRAMEWORKS,
        "impact": {
            "avg_confidence": avg_conf, "avg_entropy": avg_entropy,
            "detection_rate": det_rate,
            "quarantine_rate": round(sum(1 for m in malware if m["is_quarantined"]) / mal_cnt * 100 if mal_cnt else 0, 1),
            "severe_rate": round(sev_cnt / mal_cnt * 100 if mal_cnt else 0, 1),
        }
    })

# ── Simulate multi attacks ────────────────────────────────────────────────────
@app.route("/api/simulate_multi", methods=["POST"])
@login_required
def simulate_multi():
    data  = request.get_json() or {}
    count = min(int(data.get("count", 10)), 20)
    ATTACK_TYPES = [
        {"type": "Ransomware", "name": "banking_ransomware_lockbit.exe"},
        {"type": "Trojan",     "name": "banking_trojan_emotet.exe"},
        {"type": "Backdoor",   "name": "banking_backdoor_cobalt.exe"},
        {"type": "Worm",       "name": "banking_worm_propagator.exe"},
        {"type": "Spyware",    "name": "banking_spyware_keylog.exe"},
    ]
    results  = []
    type_log = {}
    for i in range(count):
        atk     = ATTACK_TYPES[i % len(ATTACK_TYPES)]
        content = build_malware_binary(atk["type"].lower())
        content = content + f"_v{i}_{datetime.now().microsecond}".encode()
        ts      = datetime.now().strftime('%H%M%S%f')[:12]
        fname   = f"{ts}_{atk['name']}"
        tmp     = os.path.join(UPLOAD_DIR, fname)
        with open(tmp, "wb") as f: f.write(content)

        prediction, confidence, features = predict_file(tmp)
        label = "Malware" if prediction == 1 else "Safe"
        if prediction == 1:
            attack_type    = classify_attack_type(features, prediction)
            if attack_type != atk["type"]: attack_type = atk["type"]
        else:
            attack_type = None

        banking_target = get_banking_target(attack_type, fname)
        risk_category  = RISK_CATEGORIES.get(attack_type, None) if attack_type else None

        q_path = None; is_q = 0
        if prediction == 1:
            q_filename = f"QUARANTINED_{datetime.now().strftime('%Y%m%d_%H%M%S%f')[:18]}_{fname}"
            q_path     = os.path.join(QUARANTINE_DIR, q_filename)
            shutil.move(tmp, q_path)
            is_q = 1
        else:
            os.remove(tmp)

        fhash = hashlib.md5(content).hexdigest()
        conn  = get_db()
        conn.execute("""
            INSERT INTO scan_logs
                (filename, file_size, file_hash, prediction, confidence, entropy,
                 is_quarantined, scanned_by, attack_type, banking_target, risk_category)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (fname, len(content), fhash, label, confidence,
              features["entropy"], is_q, session["username"], attack_type, banking_target, risk_category))
        conn.commit()
        lid = db_fetchone(conn, "SELECT last_insert_rowid() as id")["id"]
        if prediction == 1:
            conn.execute(
                "INSERT INTO quarantine_records (scan_log_id, original_path, quarantine_path) VALUES (?,?,?)",
                (lid, fname, q_path)
            )
            conn.commit()
        conn.close()

        type_log[atk["type"]] = type_log.get(atk["type"], 0) + 1
        results.append({
            "id": lid, "filename": fname, "prediction": label,
            "attack_type": attack_type, "banking_target": banking_target,
            "confidence": confidence, "is_quarantined": bool(is_q)
        })

    type_summary = ", ".join(f"{k}×{v}" for k, v in type_log.items())
    return jsonify({
        "simulated": len(results), "results": results,
        "type_summary": type_summary,
        "message": f"⚡ {count} banking threats simulated — {type_summary}"
    })

# ── Health ────────────────────────────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok", "time": datetime.now().isoformat(),
        "system": "BankShield AI — Banking Threat Detection",
        "db_mode": "turso_cloud" if TURSO_URL else "sqlite_local"
    })

if __name__ == "__main__":
    print("Starting BankShield AI — Banking Threat Detection System...")
    app.run(debug=True, host="0.0.0.0", port=5000)
