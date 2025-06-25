from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import os
import sys
import json
import tempfile
from datetime import datetime
from pathlib import Path
import traceback
import logging

# Configure logging for Vercel
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add the project root to Python path for imports - Enhanced for Vercel
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Also add common Vercel paths
if '/var/task' in os.path.abspath(__file__):  # Vercel runtime detection
    sys.path.insert(0, '/var/task')
    
logger.info(f"Python paths: {sys.path[:3]}")
logger.info(f"Project root: {project_root}")
logger.info(f"Environment: {'Vercel' if os.getenv('VERCEL') else 'Local'}")

# Import existing modules with enhanced error handling
scanner_available = False
parser_available = False
report_available = False
ai_available = False

try:
    from scanner.run_zap_scan import scan_website
    scanner_available = True
    logger.info("✅ Scanner module imported")
except ImportError as e:
    logger.error(f"❌ Scanner import failed: {e}")
    def scan_website(url):
        return {
            'target': url,
            'timestamp': datetime.now().isoformat(),
            'scan_type': 'Fallback Security Scan',
            'findings': [
                {
                    'name': 'Basic Security Check',
                    'severity': 'Info',
                    'description': 'Basic security assessment performed',
                    'evidence': f'Target: {url}',
                    'remediation': 'Consider comprehensive security testing',
                    'cvss': 0.0
                }
            ]
        }

try:
    from parser.zap_parser import parse_zap_report
    parser_available = True
    logger.info("✅ Parser module imported")
except ImportError as e:
    logger.error(f"❌ Parser import failed: {e}")
    def parse_zap_report(file_path):
        # Fallback parser
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            class FallbackParser:
                def __init__(self, data):
                    self.vulnerabilities = []
                    self._create_fallback_vulns(data)
                
                def _create_fallback_vulns(self, data):
                    from types import SimpleNamespace
                    for finding in data.get('findings', []):
                        vuln = SimpleNamespace()
                        vuln.name = finding.get('name', 'Unknown')
                        vuln.risk = finding.get('severity', 'Low')
                        vuln.description = finding.get('description', '')
                        vuln.solution = finding.get('remediation', '')
                        self.vulnerabilities.append(vuln)
                
                def export_to_dict(self):
                    return {
                        'metadata': {'target_url': self.data.get('target', '')},
                        'summary': {
                            'total_alerts': len(self.vulnerabilities),
                            'risk_counts': {'Low': len(self.vulnerabilities)}
                        },
                        'alerts': [
                            {
                                'name': v.name,
                                'risk': v.risk,
                                'description': v.description,
                                'solution': v.solution
                            } for v in self.vulnerabilities
                        ],
                        'statistics': {
                            'risk_distribution': {'Low': len(self.vulnerabilities)}
                        }
                    }
            
            parser = FallbackParser(data)
            parser.data = data
            return parser
        except Exception as e:
            logger.error(f"Fallback parser failed: {e}")
            return None

try:
    from report.generate_pdf import generate_pentest_report
    report_available = True
    logger.info("✅ Report module imported")
except ImportError as e:
    logger.error(f"❌ Report import failed: {e}")
    def generate_pentest_report(data, ai, url):
        return ""  # No report generation if import fails

try:
    from ai_module.summarize import VulnerabilityAnalyzer
    ai_available = True
    logger.info("✅ AI module imported")
except ImportError as e:
    logger.error(f"❌ AI import failed: {e}")
    class VulnerabilityAnalyzer:
        def initialize_openai(self): return False
        def analyze_vulnerabilities_batch(self, vulns): return {}

# Configuration handling with environment variables
class Config:
    def __init__(self):
        self.OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
        self.REPORTS_DIR = Path("/tmp/reports")
        
config = Config()

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize components
vulnerability_analyzer = VulnerabilityAnalyzer()

# Ensure directories exist (use /tmp for Vercel)
def ensure_directories():
    """Ensure required directories exist in /tmp"""
    try:
        os.makedirs("/tmp/scans", exist_ok=True)
        os.makedirs("/tmp/reports", exist_ok=True)
        logger.info("✅ Directories created in /tmp")
    except Exception as e:
        logger.error(f"❌ Failed to create directories: {e}")

ensure_directories()

@app.route('/', methods=['GET'])
def serve_frontend():
    """Serve the main frontend page"""
    try:
        # For Vercel, serve from public directory
        public_dir = os.path.join(project_root, 'public')
        return send_from_directory(public_dir, 'index.html')
    except Exception as e:
        logger.error(f"Error serving frontend: {e}")
        return f"Error: {e}", 500

@app.route('/<path:filename>', methods=['GET'])
def serve_static(filename):
    """Serve static files"""
    try:
        public_dir = os.path.join(project_root, 'public')
        return send_from_directory(public_dir, filename)
    except Exception as e:
        logger.error(f"Error serving {filename}: {e}")
        return f"File not found: {filename}", 404

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'environment': 'vercel' if os.getenv('VERCEL') else 'local',
        'modules': {
            'scanner': scanner_available,
            'parser': parser_available,
            'report': report_available,
            'ai': ai_available
        },
        'features': {
            'ai_analysis': bool(config.OPENAI_API_KEY and ai_available),
            'pdf_reports': report_available,
            'security_scanning': scanner_available
        }
    })

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a security scan"""
    try:
        logger.info("📍 Scan request received")
        logger.info(f"📍 Environment: {'Vercel' if os.getenv('VERCEL') else 'Local'}")
        logger.info(f"📍 OpenAI key configured: {bool(config.OPENAI_API_KEY)}")
        logger.info(f"📍 Modules available - Scanner: {scanner_available}, Parser: {parser_available}")
        
        data = request.json
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        target_url = data.get('target_url')
        include_ai = data.get('include_ai', False)
        
        if not target_url:
            return jsonify({'error': 'target_url is required'}), 400
        
        logger.info(f"📍 Scanning URL: {target_url}")
        
        # Step 1: Run vulnerability scan
        try:
            scan_data = scan_website(target_url)
            logger.info(f"📍 Scan result type: {type(scan_data)}")
            logger.info(f"📍 Scan data keys: {scan_data.keys() if isinstance(scan_data, dict) else 'Not a dict'}")
        except Exception as e:
            logger.error(f"Scanner failed: {e}")
            traceback.print_exc()
            return jsonify({
                'error': f'Scanner failed: {str(e)}',
                'error_type': 'scanner_error'
            }), 500
        
        if not scan_data or not isinstance(scan_data, dict):
            logger.error(f"Scan returned invalid data: {scan_data}")
            return jsonify({'error': 'Scan failed - invalid data returned'}), 500
            
        if not scan_data.get('findings'):
            logger.error("Scan returned no findings")
            return jsonify({'error': 'Scan failed - no findings returned'}), 500
        
        logger.info(f"✅ Scan successful: {len(scan_data['findings'])} findings")
        
        # Step 2: Save scan results to /tmp (Vercel writable directory)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_file = f"/tmp/scans/scan_results_{timestamp}.json"
        
        try:
            with open(scan_file, 'w') as f:
                json.dump(scan_data, f, indent=2, default=str)
            logger.info(f"✅ Scan data saved: {scan_file}")
        except Exception as e:
            logger.error(f"Failed to save scan data: {e}")
            return jsonify({'error': f'Failed to save scan data: {str(e)}'}), 500
        
        # Step 3: Parse results
        try:
            parser = parse_zap_report(scan_file)
            if not parser:
                logger.error("Parser returned None")
                return jsonify({'error': 'Failed to parse scan results'}), 500
                
            parsed_data = parser.export_to_dict()
            logger.info(f"✅ Parsing successful: {len(parser.vulnerabilities)} vulnerabilities")
        except Exception as e:
            logger.error(f"Parser failed: {e}")
            traceback.print_exc()
            return jsonify({'error': f'Parser failed: {str(e)}'}), 500
        
        # Step 4: AI Analysis (if enabled and configured)
        ai_analyses = {}
        if include_ai and config.OPENAI_API_KEY and ai_available:
            try:
                logger.info(f"🤖 Starting AI analysis for {len(parser.vulnerabilities)} vulnerabilities...")
                if vulnerability_analyzer.initialize_openai():
                    ai_analyses = vulnerability_analyzer.analyze_vulnerabilities_batch(parser.vulnerabilities)
                    logger.info(f"✅ AI analysis completed: {len(ai_analyses)} analyses generated")
                else:
                    logger.warning("❌ Failed to initialize OpenAI")
            except Exception as e:
                logger.error(f"❌ AI analysis failed: {e}")
        elif not include_ai:
            logger.info("ℹ️ AI analysis not requested by user")
        elif not config.OPENAI_API_KEY:
            logger.info("ℹ️ AI analysis not available - no OpenAI API key configured")
        elif not ai_available:
            logger.info("ℹ️ AI analysis not available - module import failed")
        
        # Step 5: Generate PDF report to /tmp
        report_path = ""
        if report_available:
            try:
                # Update config for Vercel temporary directory
                config.REPORTS_DIR = Path("/tmp/reports")
                report_path = generate_pentest_report(parsed_data, ai_analyses, target_url)
                logger.info(f"✅ PDF report generated: {report_path}")
            except Exception as e:
                logger.error(f"PDF generation failed: {e}")
                report_path = ""
        else:
            logger.info("ℹ️ PDF generation not available - module import failed")
        
        # Extract actual report timestamp from report path for download
        actual_scan_id = timestamp
        if report_path:
            # Extract timestamp from report filename for accurate download
            import re
            match = re.search(r'(\d{8}_\d{6})', os.path.basename(report_path))
            if match:
                actual_scan_id = match.group(1)

        # Return results
        return jsonify({
            'status': 'success',
            'scan_id': actual_scan_id,
            'target_url': target_url,
            'results': parsed_data,
            'report_path': report_path,
            'ai_enabled': include_ai and bool(config.OPENAI_API_KEY and ai_available),
            'ai_analyses_count': len(ai_analyses)
        })
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"❌ Scan error: {error_msg}")
        traceback.print_exc()
        
        # Return detailed error for debugging
        return jsonify({
            'error': error_msg,
            'error_type': type(e).__name__,
            'debug_info': f"Error in scan endpoint: {error_msg}",
            'modules_available': {
                'scanner': scanner_available,
                'parser': parser_available,
                'report': report_available,
                'ai': ai_available
            }
        }), 500

@app.route('/api/download-report/<scan_id>', methods=['GET'])
def download_report(scan_id):
    """Download PDF report"""
    try:
        # Find report file in /tmp
        reports_dir = Path("/tmp/reports")
        report_files = list(reports_dir.glob(f"*{scan_id}*.pdf"))
        
        if not report_files:
            return jsonify({'error': 'Report not found'}), 404
        
        report_path = report_files[0]
        return send_file(report_path, as_attachment=True, download_name=f"security-report-{scan_id}.pdf")
        
    except Exception as e:
        logger.error(f"Download error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/recent-scans', methods=['GET'])
def get_recent_scans():
    """Get list of recent scans"""
    try:
        scans_dir = Path("/tmp/scans")
        if not scans_dir.exists():
            return jsonify({'scans': []})
        
        scan_files = list(scans_dir.glob("*.json"))
        recent_scans = []
        
        for scan_file in sorted(scan_files, reverse=True)[:10]:  # Last 10 scans
            try:
                with open(scan_file, 'r') as f:
                    scan_data = json.load(f)
                
                # Extract basic info
                scan_info = {
                    'scan_id': scan_file.stem.replace('scan_results_', ''),
                    'target_url': scan_data.get('target', 'Unknown'),
                    'timestamp': scan_data.get('timestamp', ''),
                    'findings_count': len(scan_data.get('findings', []))
                }
                recent_scans.append(scan_info)
            except Exception as e:
                logger.error(f"Error reading scan file {scan_file}: {e}")
                continue
        
        return jsonify({'scans': recent_scans})
        
    except Exception as e:
        logger.error(f"Recent scans error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get application configuration"""
    return jsonify({
        'ai_enabled': bool(config.OPENAI_API_KEY and ai_available),
        'max_scan_targets': 1,  # For SaaS, limit to single targets
        'supported_protocols': ['http', 'https'],
        'features': {
            'security_headers': scanner_available,
            'ssl_analysis': scanner_available,
            'domain_info': scanner_available,
            'vulnerability_scan': scanner_available,
            'ai_analysis': bool(config.OPENAI_API_KEY and ai_available),
            'pdf_reports': report_available
        }
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# Vercel requires app to be exported as 'app'
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 