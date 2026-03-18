# BankShield AI — Deployment Guide
## Banking Sector Cyber Threat Detection System

---

## Architecture Overview
```
Netlify (Frontend/React) ←→ Vercel (Backend/Flask) ←→ Turso (Cloud SQLite DB)
```

---

## STEP 1: Setup Turso Database (Free Online SQLite)

1. Go to https://turso.tech → Sign up free
2. Create a new database:
   ```
   turso db create bankshield-db
   ```
3. Get your credentials:
   ```
   turso db show bankshield-db --url
   turso db tokens create bankshield-db
   ```
4. Save these two values:
   - `TURSO_DATABASE_URL` = `libsql://bankshield-db-xxxxx.turso.io`
   - `TURSO_AUTH_TOKEN`   = `eyJh...` (long token)

---

## STEP 2: Deploy Backend to Vercel

1. Install Vercel CLI: `npm i -g vercel`
2. Go to backend folder: `cd backend`
3. Run: `vercel`
4. Set Environment Variables in Vercel Dashboard:
   ```
   SECRET_KEY        = any_random_secret_string_here
   TURSO_DATABASE_URL = libsql://bankshield-db-xxxxx.turso.io
   TURSO_AUTH_TOKEN   = eyJh...your_token...
   ALLOWED_ORIGINS    = https://your-netlify-app.netlify.app
   ```
5. Note your Vercel URL: `https://bankshield-backend-xxxxx.vercel.app`

---

## STEP 3: Deploy Frontend to Netlify

1. Open `frontend/netlify.toml`
2. Update `REACT_APP_API_URL` with your actual Vercel URL:
   ```toml
   REACT_APP_API_URL = "https://bankshield-backend-xxxxx.vercel.app"
   ```
3. Go to https://netlify.com → New Site → Deploy from folder
4. Set Environment Variable in Netlify Dashboard:
   ```
   REACT_APP_API_URL = https://bankshield-backend-xxxxx.vercel.app
   ```
5. Deploy the `frontend` folder

---

## Local Development (Without Turso)

If TURSO_DATABASE_URL is NOT set, the backend automatically uses a local SQLite file.

```bash
# Backend
cd backend
pip install -r requirements.txt
python app.py

# Frontend (new terminal)
cd frontend
npm install
npm start
```

---

## Default Login
- Username: `admin`
- Password: `admin123`

---

## Banking Features Added

| Feature | Description |
|---------|-------------|
| Banking Target | Shows which banking system is targeted (SWIFT, ATM, Core Banking...) |
| Risk Category | PCI-DSS, RBI Compliance risk classification |
| Bank Departments | SOC heatmap with Core Banking, SWIFT, ATM, Digital Banking etc. |
| Compliance Badges | RBI, PCI-DSS, ISO 27001, SWIFT CSP, CERT-In |
| Branding | BankShield AI — Banking Threat Detection System |

---

## Attack Types → Banking Impact

| Attack | Banking Target | Risk |
|--------|---------------|------|
| Ransomware | Core Banking, SWIFT, ATM | Data Integrity & Availability |
| Trojan | Online Banking, Mobile App | Credential Theft & Fraud |
| Backdoor | Core Banking, Admin Console | Unauthorized Access |
| Worm | Branch Network, ATM Network | Network Propagation |
| Spyware | Customer PII, Card Data | Data Exfiltration (PCI-DSS) |
