# AutoPent.AI 🛡️

**AI-Powered Security Scanner** - Simple URL security scanning with AI analysis and downloadable reports.

## What it does

1. **Enter a URL** → Scans for security vulnerabilities
2. **AI Analysis** → Intelligent vulnerability assessment (optional)
3. **Download Report** → Professional PDF security report

## Features

- ✅ **HTTP Security Headers Analysis**
- ✅ **SSL/TLS Configuration Check**
- ✅ **Content Security Analysis**
- ✅ **AI-Powered Risk Assessment** (with OpenAI API)
- ✅ **Professional PDF Reports**
- ✅ **Serverless-Ready** (Vercel deployment)

## Quick Start

### Local Development

1. **Clone & Install**

   ```bash
   git clone <your-repo>
   cd AutoPent.AI
   pip install -r requirements.txt
   ```

2. **Configure (Optional AI)**

   ```bash
   cp env.example .env
   # Edit .env and add your OPENAI_API_KEY
   ```

3. **Run Locally**
   ```bash
   python run_web.py
   ```
   Visit: http://localhost:5000

### Vercel Deployment

1. **Deploy to Vercel**

   ```bash
   vercel --prod
   ```

2. **Add Environment Variables**

   - Go to Vercel Dashboard → Project Settings → Environment Variables
   - Add: `OPENAI_API_KEY` (for AI analysis)

3. **Done!** Your scanner is live.

## Environment Variables

| Variable         | Required | Description                               |
| ---------------- | -------- | ----------------------------------------- |
| `OPENAI_API_KEY` | Optional | Enables AI-powered vulnerability analysis |

## API Endpoints

- `GET /` - Main interface
- `POST /api/scan` - Start security scan
- `GET /api/download-report/<scan_id>` - Download PDF report
- `GET /api/health` - Health check

## Tech Stack

- **Backend**: Flask + Python
- **Frontend**: Vanilla JS + Modern CSS
- **AI**: OpenAI API
- **Reports**: ReportLab PDF
- **Deployment**: Vercel Serverless

## Project Structure

```
AutoPent.AI/
├── api/main.py          # Flask API
├── scanner/             # Security scanning
├── ai_module/           # AI analysis
├── report/              # PDF generation
├── public/              # Frontend
├── vercel.json          # Vercel config
└── requirements.txt     # Dependencies
```

## Contributing

This project is focused on one thing: **URL scanning with AI analysis and PDF reports**.

To maintain simplicity:

- Keep core functionality minimal
- Optimize for speed and reliability
- Ensure Vercel compatibility

---

**Made with ❤️ for simple, effective security scanning**
