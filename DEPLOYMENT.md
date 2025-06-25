# 🚀 Vercel Deployment Guide

## Quick Deploy

1. **Push to GitHub** (if not already done)

   ```bash
   git add .
   git commit -m "Ready for Vercel deployment"
   git push origin main
   ```

2. **Deploy to Vercel**

   - Go to [vercel.com](https://vercel.com)
   - Click "Import Project"
   - Select your repository
   - Click "Deploy"

3. **Add Environment Variables** (Optional - for AI features)
   - Go to Project Settings → Environment Variables
   - Add: `OPENAI_API_KEY` = `your_openai_api_key_here`
   - Redeploy if you add the API key later

## Vercel Configuration

✅ **Already configured in `vercel.json`:**

- Python runtime setup
- Route handling for API and static files
- Function timeout (30s) and memory (1GB)
- Security headers
- Cache control

## Test Your Deployment

After deployment, test these endpoints:

1. **Homepage**: `https://your-app.vercel.app/`
2. **Health Check**: `https://your-app.vercel.app/api/health`
3. **Try a scan** through the web interface

## Features Enabled

✅ **Core Functionality**

- URL security scanning
- HTTP security headers analysis
- SSL/TLS verification
- Content security analysis
- Professional PDF reports

✅ **AI Analysis** (if OpenAI API key provided)

- Intelligent vulnerability assessment
- Risk analysis and recommendations
- Enhanced PDF reports with AI insights

## Troubleshooting

**Function Timeout Issues:**

- Scans are optimized for <30 seconds
- If still timing out, check target URL accessibility

**PDF Download Issues:**

- Reports are stored in `/tmp` (Vercel writable directory)
- Downloads should work immediately after scan completion

**AI Not Working:**

- Verify `OPENAI_API_KEY` is set in Vercel environment variables
- Check OpenAI API key has sufficient credits

## Performance Notes

- **Function Memory**: 1GB allocated for PDF generation
- **Timeout**: 30 seconds maximum per scan
- **Concurrency**: Supports multiple simultaneous scans
- **Storage**: Temporary files in `/tmp` (cleared between function calls)

---

**Your AutoPent.AI is now ready for production! 🎉**
