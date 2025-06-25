from http.server import BaseHTTPRequestHandler
import json
import sys
import os
import traceback

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        debug_info = {
            'python_version': sys.version,
            'python_path': sys.path[:5],
            'current_dir': os.getcwd(),
            'file_location': __file__,
            'environment': 'vercel' if os.getenv('VERCEL') else 'local',
            'openai_key_available': bool(os.getenv('OPENAI_API_KEY')),
            'imports': {}
        }
        
        # Test imports
        modules_to_test = [
            'scanner.run_zap_scan',
            'parser.zap_parser', 
            'report.generate_pdf',
            'ai_module.summarize',
            'config'
        ]
        
        for module in modules_to_test:
            try:
                __import__(module)
                debug_info['imports'][module] = 'SUCCESS'
            except Exception as e:
                debug_info['imports'][module] = f'FAILED: {str(e)}'
        
        # Test scanner function specifically
        try:
            from scanner.run_zap_scan import scan_website
            test_result = scan_website('https://httpbin.org/status/200')
            debug_info['scanner_test'] = {
                'status': 'SUCCESS',
                'result_type': str(type(test_result)),
                'has_findings': bool(test_result.get('findings') if isinstance(test_result, dict) else False),
                'findings_count': len(test_result.get('findings', [])) if isinstance(test_result, dict) else 0
            }
        except Exception as e:
            debug_info['scanner_test'] = {
                'status': 'FAILED',
                'error': str(e),
                'traceback': traceback.format_exc()
            }
        
        response = json.dumps(debug_info, indent=2)
        self.wfile.write(response.encode('utf-8')) 