# 🤖 AutoPent.AI - AI-Augmented Web Pentesting Assistant

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OpenAI](https://img.shields.io/badge/AI-OpenAI%20GPT--4-green.svg)](https://openai.com/)

A comprehensive, AI-powered web application security testing assistant that combines automated vulnerability scanning with intelligent analysis and professional reporting.

## 🌟 Features

- **🕷️ Automated Scanning**: OWASP ZAP integration for comprehensive vulnerability detection
- **🤖 AI Analysis**: OpenAI GPT-4 powered vulnerability explanation and remediation
- **📊 CVSS Scoring**: Automated risk assessment with CVSS v3.1 calculations
- **📄 Professional Reports**: Beautiful PDF reports with executive summaries
- **🎯 Web Interface**: Modern Streamlit UI for easy interaction
- **⚡ CLI Support**: Command-line interface for automation and CI/CD integration

## 🏗️ Architecture

```
AutoPent.AI/
├── scanner/           # ZAP integration and scanning logic
├── parser/            # Report parsing and data extraction
├── ai_module/         # OpenAI integration for vulnerability analysis
├── cvss/              # CVSS calculation and risk assessment
├── report/            # PDF report generation
├── streamlit_ui/      # Web interface
├── scans/             # Scan results storage
├── reports/           # Generated reports
└── main.py            # CLI orchestrator
```

## 🚀 Quick Start

### 1. Prerequisites

- Python 3.8+
- OWASP ZAP installed and accessible via command line
- OpenAI API key (for AI analysis)

### 2. Installation

```bash
# Clone the repository
git clone <repository-url>
cd AutoPent.AI

# Install dependencies
pip install -r requirements.txt

# Setup environment variables
cp env_example.txt .env
# Edit .env and add your OpenAI API key
```

### 3. Install OWASP ZAP

#### Windows:

```bash
# Download from https://www.zaproxy.org/download/
# Install and ensure zap-cli is in PATH
pip install zaproxy
```

#### Linux/macOS:

```bash
# Using package manager
sudo apt-get install zaproxy  # Ubuntu/Debian
brew install zaproxy          # macOS

# Or download from official site
wget https://github.com/zaproxy/zaproxy/releases/latest/download/ZAP_LINUX.tar.gz
```

### 4. Quick Scan

#### Command Line Interface:

```bash
# Basic scan
python main.py --url https://example.com

# Verbose output
python main.py --url https://example.com --verbose

# Custom output directory
python main.py --url https://example.com --output-dir ./custom_reports
```

#### Web Interface:

```bash
# Start Streamlit web interface
streamlit run streamlit_ui/app.py

# Open browser to http://localhost:8501
# Enter target URL and click "Start Security Scan"
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file with the following variables:

```bash
# Required for AI analysis
OPENAI_API_KEY=your_openai_api_key_here

# Optional ZAP configuration
ZAP_PROXY_HOST=127.0.0.1
ZAP_PROXY_PORT=8080

# Optional report customization
REPORT_AUTHOR=Your Security Team
REPORT_TITLE=Custom Security Assessment
```

### Configuration File

Edit `config.py` to customize:

- Scan parameters (depth, timeout, policies)
- Risk thresholds and CVSS settings
- Report templates and styling
- AI prompts and models

## 📊 Usage Examples

### 1. Basic Web App Scan

```bash
python main.py --url https://your-web-app.com
```

**Output:**

- JSON scan report in `scans/` directory
- AI analysis of vulnerabilities
- Professional PDF report in `reports/` directory

### 2. Using Existing Scan Report

```bash
python main.py --url https://example.com --skip-scan --scan-report ./scans/existing_report.json
```

### 3. Streamlit Web Interface

```bash
streamlit run streamlit_ui/app.py
```

Features:

- Interactive scanning interface
- Real-time progress tracking
- Visual analytics and charts
- Report management and download

## 📄 Report Features

### Executive Summary

- Risk distribution overview
- Key findings highlights
- Business impact assessment
- Remediation timeline

### Technical Details

- Detailed vulnerability descriptions
- AI-powered explanations and solutions
- CVSS v3.1 scoring with reasoning
- Code examples and proof-of-concepts

### Professional Format

- Clean, modern PDF layout
- Risk-based color coding
- Charts and visualizations
- Customizable branding

## 🔒 Security Considerations

- **API Keys**: Store OpenAI API keys securely in environment variables
- **Network Access**: ZAP requires network access to target applications
- **Permissions**: Ensure you have authorization to test target applications
- **Data Handling**: Scan reports may contain sensitive information

## 🧪 Testing

### Test Individual Components

```bash
# Test ZAP scanner
python scanner/run_zap_scan.py https://example.com

# Test report parser
python parser/zap_parser.py ./scans/sample_report.json

# Test AI analysis
python ai_module/summarize.py

# Test CVSS calculation
python cvss/calculate.py

# Test report generation
python report/generate_pdf.py
```

### Sample Test Target

Use deliberately vulnerable applications for testing:

- [DVWA (Damn Vulnerable Web Application)](http://www.dvwa.co.uk/)
- [WebGoat](https://owasp.org/www-project-webgoat/)
- [Mutillidae II](https://sourceforge.net/projects/mutillidae/)

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Format code
black .
flake8 .
```

## 📚 Documentation

### API Reference

- [ZAP API Documentation](https://www.zaproxy.org/docs/api/)
- [OpenAI API Reference](https://platform.openai.com/docs/api-reference)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)

### Security Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## 🐛 Troubleshooting

### Common Issues

#### ZAP Connection Failed

```bash
# Check if ZAP is installed
zap-cli --version

# Start ZAP daemon manually
zap-cli start
```

#### OpenAI API Errors

```bash
# Verify API key is set
echo $OPENAI_API_KEY

# Check API quota and billing
# Visit https://platform.openai.com/account/usage
```

#### Permission Errors

```bash
# Ensure proper file permissions
chmod +x main.py
sudo chown -R $USER:$USER .
```

### Debug Mode

```bash
# Enable verbose logging
python main.py --url https://example.com --verbose

# Check log files
tail -f autopent.log
```

## 🔄 Roadmap

- [ ] **Multi-target scanning** - Scan multiple URLs in parallel
- [ ] **API endpoint testing** - Dedicated REST API security testing
- [ ] **Authentication handling** - Support for authenticated scans
- [ ] **Custom payloads** - User-defined injection payloads
- [ ] **CI/CD integration** - GitHub Actions and Jenkins plugins
- [ ] **Database storage** - Persistent scan history and trending
- [ ] **Team collaboration** - Multi-user support and sharing
- [ ] **Mobile app testing** - Android/iOS security assessment

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OWASP ZAP Team** - For the excellent vulnerability scanner
- **OpenAI** - For providing powerful AI capabilities
- **Security Community** - For continuous research and tool development

## 📞 Support

- 📧 **Email**: support@autopent.ai
- 💬 **Discord**: [Join our community](https://discord.gg/autopent)
- 🐛 **Issues**: [GitHub Issues](https://github.com/username/autopent-ai/issues)
- 📖 **Wiki**: [Project Wiki](https://github.com/username/autopent-ai/wiki)

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Always ensure you have proper permission before scanning any web application. The authors are not responsible for any misuse of this tool.

**🔒 Built with Security in Mind** | **🤖 Powered by AI** | **🌟 Open Source**
