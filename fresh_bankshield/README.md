# BankShield AI — Banking Sector Cyber Threat Detection

## Folder Structure
```
bankshield/
├── backend/          ← Deploy to Vercel
│   ├── api/
│   │   └── index.py  ← Main Flask app
│   ├── ml_model/     ← ML model files
│   ├── requirements.txt
│   └── vercel.json
└── frontend/         ← Deploy to Netlify
    ├── src/
    ├── public/
    ├── package.json
    └── netlify.toml
```

## Deploy Steps

### 1. Vercel (Backend)
- Import GitHub repo → Set Root Directory: `backend`
- Add Environment Variables:
  - `SECRET_KEY` = any random string
  - `ALLOWED_ORIGINS` = https://your-app.netlify.app
- Deploy → copy your Vercel URL

### 2. Netlify (Frontend)
- Import GitHub repo → Set Base directory: `frontend`
- Build command: `npm run build`
- Publish directory: `frontend/build`
- Add Environment Variable:
  - `REACT_APP_API_URL` = https://your-vercel-url.vercel.app
- Deploy

### 3. Update CORS
- Go back to Vercel → Settings → Environment Variables
- Update `ALLOWED_ORIGINS` with your actual Netlify URL
- Redeploy

## Login
- Username: `admin`
- Password: `admin123`
