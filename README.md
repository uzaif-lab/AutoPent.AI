# AutoPent.AI - Web Application

🛡️ **AI-Powered Security Scanner** - Professional web application ready for SaaS deployment.

## 🚀 Quick Deploy to Vercel

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/your-username/AutoPent.AI)

1. **Fork this repository**
2. **Connect to Vercel**
3. **Add environment variables:**
   - `OPENAI_API_KEY` - Your OpenAI API key (optional for AI analysis)
4. **Deploy!** ✨

## 🏗️ Project Structure

```
AutoPent.AI/
├── api/                    # Flask API backend
│   └── main.py            # Main API routes
├── public/                # Frontend static files
│   ├── index.html         # Web application
│   ├── styles.css         # UI styles
│   └── app.js            # Frontend logic
├── scanner/              # Security scanning
├── parser/               # Results parsing
├── report/               # PDF generation
├── ai_module/            # AI analysis
├── vercel.json           # Vercel config
└── requirements.txt      # Dependencies
```

## 🌟 Features

- **Security Scanning**: Headers, SSL/TLS, domain info, vulnerabilities
- **AI Analysis**: OpenAI GPT-4 powered insights and recommendations
- **PDF Reports**: Professional downloadable reports
- **Modern UI**: Responsive design with real-time progress

## ⚙️ Local Development

### Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment (optional)
export OPENAI_API_KEY="your_openai_api_key_here"

# Run the application
python run_web.py
```

Open `http://localhost:5000` in your browser.

## 🌐 Environment Variables

| Variable         | Required | Description                    |
| ---------------- | -------- | ------------------------------ |
| `OPENAI_API_KEY` | Optional | OpenAI API key for AI analysis |

## 📱 API Endpoints

- `GET /` - Web application
- `POST /api/scan` - Start security scan
- `GET /api/download-report/<scan_id>` - Download PDF report
- `GET /api/health` - Health check

## 🚀 Deployment

### Vercel (Recommended)

- One-click deployment with the button above
- Automatic HTTPS and global CDN
- Serverless functions

### Other Options

- **Railway**: `railway deploy`
- **Heroku**: `git push heroku main`

## 📖 Usage

1. **Enter target URL** - Website to scan
2. **Enable AI analysis** (optional) - Get detailed insights
3. **Start scan** - Comprehensive security assessment
4. **View results** - Interactive vulnerability dashboard
5. **Download report** - Professional PDF report

---

**Ready to deploy your security scanner? Start with Vercel!** 🚀
