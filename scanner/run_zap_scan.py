#!/usr/bin/env python3
"""
Advanced Web Security Scanner
API-based vulnerability scanning suitable for online hosting
"""

import requests
import ssl
import socket
import json

# Optional imports for enhanced domain analysis
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("Warning: dns.resolver not available. DNSSEC checks will be skipped.")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("Warning: whois not available. Domain age checks will be skipped.")
import asyncio
import aiohttp
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import re
import logging
from typing import Dict, List, Any
import warnings
import urllib3

# Suppress SSL warnings - we're intentionally testing insecure connections
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

class WebSecurityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AutoPent.AI Security Scanner 1.0'
        })
        # Disable SSL warnings for this session since we're security testing
        self.session.verify = False
        self.timeout = 10
        
    def scan_target(self, target_url: str) -> Dict[str, Any]:
        """
        Main scanning function that performs comprehensive security analysis
        """
        print(f"🔍 Starting security scan for: {target_url}")
        
        # Parse URL
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc
        
        scan_results = {
            'target': target_url,
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'scan_type': 'API-based Security Scan',
            'findings': []
        }
        
        try:
            # 1. HTTP Security Headers Analysis
            print("📋 Analyzing HTTP security headers...")
            headers_findings = self._check_security_headers(target_url)
            scan_results['findings'].extend(headers_findings)
            
            # 2. SSL/TLS Certificate Analysis
            print("🔒 Analyzing SSL/TLS configuration...")
            ssl_findings = self._check_ssl_config(domain)
            scan_results['findings'].extend(ssl_findings)
            
            # 3. Domain Information Gathering
            print("🌐 Gathering domain information...")
            domain_findings = self._analyze_domain(domain)
            scan_results['findings'].extend(domain_findings)
            
            # 4. Content Security Analysis
            print("📄 Analyzing page content...")
            content_findings = self._analyze_content(target_url)
            scan_results['findings'].extend(content_findings)
            
            # 5. Common Vulnerability Checks
            print("🔎 Checking for common vulnerabilities...")
            vuln_findings = self._check_common_vulnerabilities(target_url)
            scan_results['findings'].extend(vuln_findings)
            
            print(f"✅ Scan completed. Found {len(scan_results['findings'])} findings.")
            
        except Exception as e:
            logging.error(f"Scan error: {e}")
            scan_results['findings'].append({
                'name': 'Scan Error',
                'severity': 'Info',
                'description': f'Error during scanning: {str(e)}',
                'evidence': '',
                'remediation': 'Ensure the target URL is accessible and try again.',
                'cvss': 0.0
            })
        
        return scan_results
    
    def _check_security_headers(self, url: str) -> List[Dict]:
        """Check for missing or misconfigured security headers"""
        findings = []
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            headers = response.headers
            
            # Security headers to check
            security_headers = {
                'Strict-Transport-Security': {
                    'severity': 'Medium',
                    'description': 'HTTP Strict Transport Security (HSTS) header missing',
                    'remediation': 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" header'
                },
                'Content-Security-Policy': {
                    'severity': 'Medium', 
                    'description': 'Content Security Policy (CSP) header missing',
                    'remediation': 'Implement a Content Security Policy to prevent XSS attacks'
                },
                'X-Frame-Options': {
                    'severity': 'Medium',
                    'description': 'X-Frame-Options header missing - clickjacking protection',
                    'remediation': 'Add "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" header'
                },
                'X-Content-Type-Options': {
                    'severity': 'Low',
                    'description': 'X-Content-Type-Options header missing',
                    'remediation': 'Add "X-Content-Type-Options: nosniff" header'
                },
                'Referrer-Policy': {
                    'severity': 'Low',
                    'description': 'Referrer-Policy header missing',
                    'remediation': 'Add "Referrer-Policy: strict-origin-when-cross-origin" header'
                }
            }
            
            # Check for missing headers
            for header, info in security_headers.items():
                if header not in headers:
                    findings.append({
                        'name': f'Missing Security Header: {header}',
                        'severity': info['severity'],
                        'description': info['description'],
                        'evidence': f'Header "{header}" not found in response',
                        'remediation': info['remediation'],
                        'cvss': 4.0 if info['severity'] == 'Medium' else 2.0
                    })
            
            # Check for problematic headers
            if 'Server' in headers:
                findings.append({
                    'name': 'Information Disclosure - Server Header',
                    'severity': 'Low',
                    'description': 'Server header reveals technology information',
                    'evidence': f'Server: {headers["Server"]}',
                    'remediation': 'Remove or obfuscate the Server header',
                    'cvss': 1.0
                })
                
        except Exception as e:
            logging.error(f"Header check error: {e}")
            
        return findings
    
    def _check_ssl_config(self, domain: str) -> List[Dict]:
        """Analyze SSL/TLS configuration"""
        findings = []
        
        try:
            # Check SSL certificate
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiry
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        severity = 'High' if days_until_expiry < 7 else 'Medium'
                        findings.append({
                            'name': 'SSL Certificate Expiring Soon',
                            'severity': severity,
                            'description': f'SSL certificate expires in {days_until_expiry} days',
                            'evidence': f'Certificate expires: {not_after}',
                            'remediation': 'Renew SSL certificate before expiration',
                            'cvss': 7.0 if severity == 'High' else 5.0
                        })
                    
                    # Check certificate subject
                    subject = dict(x[0] for x in cert['subject'])
                    cn = subject.get('commonName', '')
                    
                    # Check if domain matches CN (including wildcard certificates)
                    domain_matches = False
                    if cn == domain:
                        domain_matches = True
                    elif cn.startswith('*.'):
                        # Wildcard certificate - check if domain matches
                        wildcard_domain = cn[2:]  # Remove '*.'
                        if domain == wildcard_domain or domain.endswith(f'.{wildcard_domain}'):
                            domain_matches = True
                    
                    if not domain_matches:
                        findings.append({
                            'name': 'SSL Certificate Name Mismatch',
                            'severity': 'High',
                            'description': 'SSL certificate common name does not match domain',
                            'evidence': f'Certificate CN: {cn}, Domain: {domain}',
                            'remediation': 'Ensure SSL certificate matches the domain name',
                            'cvss': 8.0
                        })
                        
        except ssl.SSLError as e:
            findings.append({
                'name': 'SSL Configuration Issue',
                'severity': 'High',
                'description': 'SSL/TLS configuration problem detected',
                'evidence': str(e),
                'remediation': 'Fix SSL/TLS configuration and certificate issues',
                'cvss': 7.5
            })
        except Exception as e:
            if "443" in str(e):
                findings.append({
                    'name': 'No HTTPS Support',
                    'severity': 'Medium',
                    'description': 'Website does not support HTTPS',
                    'evidence': 'Port 443 not accessible',
                    'remediation': 'Implement HTTPS with valid SSL certificate',
                    'cvss': 5.0
                })
                
        return findings
    
    def _analyze_domain(self, domain: str) -> List[Dict]:
        """Analyze domain information and DNS records"""
        findings = []
        
        try:
            # DNS Security checks (only if dns module is available)
            if DNS_AVAILABLE:
                try:
                    # Check for DNSSEC
                    resolver = dns.resolver.Resolver()
                    resolver.flags = dns.flags.DO  # DNSSEC OK bit
                    
                    try:
                        answer = resolver.resolve(domain, 'A')
                        # If we got here without exception, check if DNSSEC is actually validated
                        # This is a simplified check - in practice, DNSSEC validation is complex
                        if not hasattr(answer.response, 'flags') or not (answer.response.flags & dns.flags.AD):
                            findings.append({
                                'name': 'DNSSEC Not Implemented',
                                'severity': 'Low',
                                'description': 'Domain does not implement DNSSEC',
                                'evidence': 'DNSSEC validation not confirmed',
                                'remediation': 'Implement DNSSEC for DNS security',
                                'cvss': 2.0
                            })
                    except dns.resolver.NoAnswer:
                        pass
                    except Exception:
                        # Don't report DNSSEC as missing if we can't properly check
                        pass
                        
                except Exception:
                    pass
            
            # WHOIS information (basic check, only if whois module is available)
            if WHOIS_AVAILABLE:
                try:
                    w = whois.whois(domain)
                    if w.creation_date:
                        if isinstance(w.creation_date, list):
                            creation_date = w.creation_date[0]
                        else:
                            creation_date = w.creation_date
                        
                        domain_age = (datetime.now() - creation_date).days
                        
                        if domain_age < 30:
                            findings.append({
                                'name': 'Recently Registered Domain',
                                'severity': 'Low',
                                'description': f'Domain registered recently ({domain_age} days ago)',
                                'evidence': f'Creation date: {creation_date}',
                                'remediation': 'Verify domain legitimacy for recently registered domains',
                                'cvss': 1.0
                            })
                except Exception:
                    pass
                
        except Exception as e:
            logging.error(f"Domain analysis error: {e}")
            
        return findings
    
    def _analyze_content(self, url: str) -> List[Dict]:
        """Analyze page content for security issues"""
        findings = []
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for forms without CSRF protection
            forms = soup.find_all('form')
            for form in forms:
                if not form.find('input', {'name': re.compile(r'csrf|token', re.I)}):
                    findings.append({
                        'name': 'Form Without CSRF Protection',
                        'severity': 'Medium',
                        'description': 'Form found without apparent CSRF protection',
                        'evidence': f'Form action: {form.get("action", "N/A")}',
                        'remediation': 'Implement CSRF tokens in all forms',
                        'cvss': 4.0
                    })
            
            # Check for inline JavaScript
            scripts = soup.find_all('script')
            inline_scripts = [s for s in scripts if s.string and s.string.strip()]
            
            if inline_scripts:
                findings.append({
                    'name': 'Inline JavaScript Detected',
                    'severity': 'Low',
                    'description': f'Found {len(inline_scripts)} inline JavaScript blocks',
                    'evidence': 'Inline scripts can pose XSS risks',
                    'remediation': 'Move JavaScript to external files and implement CSP',
                    'cvss': 2.0
                })
            
            # Check for password fields without HTTPS
            if urlparse(url).scheme == 'http':
                password_fields = soup.find_all('input', {'type': 'password'})
                if password_fields:
                    findings.append({
                        'name': 'Password Field Over HTTP',
                        'severity': 'High',
                        'description': 'Password input field transmitted over unencrypted HTTP',
                        'evidence': 'Password field found on HTTP page',
                        'remediation': 'Use HTTPS for all pages with sensitive input fields',
                        'cvss': 8.0
                    })
                    
        except Exception as e:
            logging.error(f"Content analysis error: {e}")
            
        return findings
    
    def _check_common_vulnerabilities(self, url: str) -> List[Dict]:
        """Check for common web vulnerabilities"""
        findings = []
        
        try:
            # Check for common admin paths
            admin_paths = [
                '/admin', '/admin/', '/administrator', '/wp-admin', 
                '/login', '/dashboard', '/panel', '/control'
            ]
            
            accessible_admin = []
            for path in admin_paths:
                try:
                    test_url = urljoin(url, path)
                    response = self.session.get(test_url, timeout=5, allow_redirects=False)
                    if response.status_code in [200, 301, 302]:
                        accessible_admin.append(path)
                except:
                    continue
            
            if accessible_admin:
                findings.append({
                    'name': 'Accessible Admin Paths',
                    'severity': 'Medium',
                    'description': 'Administrative paths are accessible',
                    'evidence': f'Accessible paths: {", ".join(accessible_admin)}',
                    'remediation': 'Secure administrative interfaces with proper authentication',
                    'cvss': 4.0
                })
            
            # Check for directory listing
            try:
                response = self.session.get(url, timeout=self.timeout)
                if 'Index of /' in response.text or 'Directory Listing' in response.text:
                    findings.append({
                        'name': 'Directory Listing Enabled',
                        'severity': 'Medium',
                        'description': 'Web server directory listing is enabled',
                        'evidence': 'Directory listing detected in response',
                        'remediation': 'Disable directory listing in web server configuration',
                        'cvss': 3.0
                    })
            except:
                pass
                
            # Check for common backup files
            backup_files = [
                '/.git/', '/backup/', '/.env', '/config.php.bak',
                '/database.sql', '/.htaccess'
            ]
            
            found_backups = []
            for backup in backup_files:
                try:
                    test_url = urljoin(url, backup)
                    response = self.session.get(test_url, timeout=5, allow_redirects=False)
                    if response.status_code == 200:
                        found_backups.append(backup)
                except:
                    continue
            
            if found_backups:
                findings.append({
                    'name': 'Exposed Backup/Config Files',
                    'severity': 'High',
                    'description': 'Sensitive backup or configuration files are accessible',
                    'evidence': f'Accessible files: {", ".join(found_backups)}',
                    'remediation': 'Remove or properly protect sensitive files',
                    'cvss': 7.0
                })
                
        except Exception as e:
            logging.error(f"Vulnerability check error: {e}")
            
        return findings


def scan_website(target_url: str, scan_options: Dict = None) -> Dict[str, Any]:
    """
    Main function to scan a website for security vulnerabilities
    """
    scanner = WebSecurityScanner()
    return scanner.scan_target(target_url)


if __name__ == "__main__":
    # Test the scanner
    test_url = "https://example.com"
    results = scan_website(test_url)
    print(json.dumps(results, indent=2)) 