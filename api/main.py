from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import os
import sys
import json
import tempfile
from datetime import datetime
from pathlib import Path
import traceback

# Add the project root to Python path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import existing modules with error handling
try:
    from scanner.run_zap_scan import scan_website
    from parser.zap_parser import parse_zap_report
    from report.generate_pdf import generate_pentest_report
    from ai_module.summarize import VulnerabilityAnalyzer
    from config import config
    print("✅ All modules imported successfully")
except ImportError as import_error:
    error_msg = str(import_error)
    print(f"❌ Import error: {error_msg}")
    # Create fallback functions
    def scan_website(url):
        return {'error': f'Scanner module not available: {error_msg}'}
    def parse_zap_report(file):
        return None
    def generate_pentest_report(data, ai, url):
        return ""
    class VulnerabilityAnalyzer:
        def initialize_openai(self): return False
        def analyze_vulnerabilities_batch(self, vulns): return {}
    
    class FakeConfig:
        OPENAI_API_KEY = ""
        REPORTS_DIR = Path("reports")
    config = FakeConfig()

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize components
vulnerability_analyzer = VulnerabilityAnalyzer()

@app.route('/', methods=['GET'])
def serve_frontend():
    """Serve the main frontend page"""
    return send_from_directory('../public', 'index.html')

@app.route('/<path:filename>', methods=['GET'])
def serve_static(filename):
    """Serve static files"""
    return send_from_directory('../public', filename)

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'features': {
            'ai_analysis': bool(config.OPENAI_API_KEY),
            'pdf_reports': True,
            'security_scanning': True
        }
    })

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a security scan"""
    try:
        print("📍 Scan request received")
        print(f"📍 Python path: {sys.path}")
        print(f"📍 Current directory: {os.getcwd()}")
        print(f"📍 OpenAI key configured: {bool(config.OPENAI_API_KEY)}")
        data = request.json
        target_url = data.get('target_url')
        include_ai = data.get('include_ai', False)
        
        if not target_url:
            return jsonify({'error': 'target_url is required'}), 400
        
        # Step 1: Run vulnerability scan
        scan_data = scan_website(target_url)
        if not scan_data or not scan_data.get('findings'):
            return jsonify({'error': 'Scan failed - no data returned'}), 500
        
        # Step 2: Save scan results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_file = f"scans/scan_results_{timestamp}.json"
        
        # Ensure scans directory exists
        os.makedirs("scans", exist_ok=True)
        
        with open(scan_file, 'w') as f:
            json.dump(scan_data, f, indent=2, default=str)
        
        # Step 3: Parse results
        parser = parse_zap_report(scan_file)
        if not parser:
            return jsonify({'error': 'Failed to parse scan results'}), 500
        
        parsed_data = parser.export_to_dict()
        
        # Step 4: AI Analysis (if enabled and configured)
        ai_analyses = {}
        if include_ai and config.OPENAI_API_KEY:
            try:
                print(f"🤖 Starting AI analysis for {len(parser.vulnerabilities)} vulnerabilities...")
                if vulnerability_analyzer.initialize_openai():
                    ai_analyses = vulnerability_analyzer.analyze_vulnerabilities_batch(parser.vulnerabilities)
                    print(f"✅ AI analysis completed: {len(ai_analyses)} analyses generated")
                else:
                    print("❌ Failed to initialize OpenAI")
            except Exception as e:
                print(f"❌ AI analysis failed: {e}")
        elif not include_ai:
            print("ℹ️ AI analysis not requested by user")
        elif not config.OPENAI_API_KEY:
            print("ℹ️ AI analysis not available - no OpenAI API key configured")
        
        # Step 5: Generate PDF report
        try:
            report_path = generate_pentest_report(parsed_data, ai_analyses, target_url)
        except Exception as e:
            print(f"PDF generation failed: {e}")
            report_path = ""
        
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
            'ai_enabled': include_ai and bool(config.OPENAI_API_KEY),
            'ai_analyses_count': len(ai_analyses)
        })
        
    except Exception as e:
        error_msg = str(e)
        print(f"❌ Scan error: {error_msg}")
        traceback.print_exc()
        
        # Return detailed error for debugging
        return jsonify({
            'error': error_msg,
            'error_type': type(e).__name__,
            'debug_info': f"Error in scan endpoint: {error_msg}"
        }), 500

@app.route('/api/download-report/<scan_id>', methods=['GET'])
def download_report(scan_id):
    """Download PDF report"""
    try:
        # Find report file
        reports_dir = Path(config.REPORTS_DIR)
        report_files = list(reports_dir.glob(f"*{scan_id}*.pdf"))
        
        if not report_files:
            return jsonify({'error': 'Report not found'}), 404
        
        report_path = report_files[0]
        return send_file(report_path, as_attachment=True)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/recent-scans', methods=['GET'])
def get_recent_scans():
    """Get list of recent scans"""
    try:
        scans_dir = Path("scans")
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
                    'target_url': scan_data.get('target_url', 'Unknown'),
                    'timestamp': scan_data.get('timestamp', ''),
                    'findings_count': len(scan_data.get('findings', []))
                }
                recent_scans.append(scan_info)
            except:
                continue
        
        return jsonify({'scans': recent_scans})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get application configuration"""
    return jsonify({
        'ai_enabled': bool(config.OPENAI_API_KEY),
        'max_scan_targets': 1,  # For SaaS, limit to single targets
        'supported_protocols': ['http', 'https'],
        'features': {
            'security_headers': True,
            'ssl_analysis': True,
            'domain_info': True,
            'vulnerability_scan': True,
            'ai_analysis': bool(config.OPENAI_API_KEY),
            'pdf_reports': True
        }
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 