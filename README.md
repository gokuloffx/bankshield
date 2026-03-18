# Cyber Attack Prediction & Malware Detection System
## Using Machine Learning (Random Forest)

A full-stack cybersecurity application with React.js frontend, Python Flask backend,
SQLite database, and a trained Random Forest classifier.

---

## Project Structure

```
cyber_malware_project/
├── ml_model/
│   ├── train_model.py          # Train Random Forest on malware dataset
│   ├── random_forest_model.pkl # Trained model (generated after training)
│   ├── scaler.pkl              # Feature scaler
│   └── model_metadata.json     # Accuracy metrics
├── backend/
│   ├── app.py                  # Flask REST API
│   ├── requirements.txt
│   └── uploads/                # Temp upload directory
├── frontend/
│   ├── public/index.html
│   ├── package.json
│   └── src/
│       ├── App.js
│       ├── api.js
│       ├── index.css
│       ├── components/
│       │   ├── AuthContext.js
│       │   ├── Layout.js
│       │   └── Sidebar.js
│       └── pages/
│           ├── Login.js
│           ├── Dashboard.js
│           ├── Scanner.js
│           ├── Quarantine.js
│           ├── Logs.js
│           ├── Alerts.js
│           └── ModelInfo.js
├── quarantine/                 # Isolated malware files
├── instance/                   # SQLite database
└── README.md
```

---

## Setup & Run

### Step 1 — Train the ML Model
```bash
cd ml_model
pip install scikit-learn numpy pandas
python train_model.py
```
Expected output: 100% accuracy on synthetic Kaggle-style dataset.

### Step 2 — Start Flask Backend
```bash
cd backend
pip install flask flask-cors scikit-learn numpy pandas
python app.py
```
Backend runs on: http://localhost:5000

### Step 3 — Start React Frontend
```bash
cd frontend
npm install
npm start
```
Frontend runs on: http://localhost:3000

---

## Default Login
- **Username:** admin
- **Password:** admin123

---

## Features

| Feature | Description |
|---------|-------------|
| 🔐 Authentication | Login / logout with session management |
| 🔍 File Scanner | Upload any file for ML-based malware detection |
| ☣️ Auto Quarantine | Detected malware files automatically isolated |
| 📊 Dashboard | Real-time stats, charts, scan trends |
| 📋 Scan Logs | Complete history with filtering & search |
| ⚠️ Alerts | Malware detection notifications with severity |
| 🤖 Model Info | Random Forest metrics & feature importance |
| ⚡ Attack Simulation | Demo mode for manual malware testing |

---

## ML Model Details

- **Algorithm:** Random Forest Classifier (200 trees)
- **Dataset:** Kaggle Malware Dataset (synthetic PE features)
- **Features:** 20 PE-based features (entropy, imports, sections, etc.)
- **Accuracy:** 100% | Precision: 100% | Recall: 100% | F1: 100%

### Key Features Used
1. `high_entropy_code` — High entropy indicates packed/encrypted malware
2. `dll_characteristics` — DLL flags reveal suspicious executable properties
3. `timestamp_valid` — Invalid timestamps common in malware
4. `entropy` — Overall file entropy
5. `imports_crypto` — Crypto API imports suggest ransomware

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | User login |
| POST | `/api/auth/logout` | User logout |
| GET  | `/api/auth/me` | Current user info |
| POST | `/api/scan` | Upload & scan a file |
| POST | `/api/simulate_attack` | Simulate malware demo |
| GET  | `/api/logs` | Get all scan logs |
| GET  | `/api/quarantine` | Get quarantine records |
| POST | `/api/quarantine/:id/restore` | Restore file |
| DELETE | `/api/quarantine/:id/delete` | Delete permanently |
| GET  | `/api/stats` | Dashboard statistics |
| GET  | `/api/model/info` | ML model metadata |

---

## Tech Stack
- **Frontend:** React.js, React Router, Recharts, Axios
- **Backend:** Python Flask, Flask-CORS
- **Database:** SQLite3
- **ML:** Scikit-learn Random Forest, NumPy, Pandas
