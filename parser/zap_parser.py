#!/usr/bin/env python3
"""
Enhanced ZAP Report Parser
Handles both ZAP format and custom API-based scan results
"""
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

from config import config

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    """Vulnerability data class"""
    name: str
    risk: str
    confidence: str = "High"
    url: str = ""
    description: str = ""
    solution: str = ""
    reference: str = ""
    cwe_id: Optional[str] = None
    wasc_id: Optional[str] = None
    instances: List[Dict] = None
    param: str = ""
    attack: str = ""
    evidence: str = ""
    method: str = "GET"
    
    def __post_init__(self):
        if self.instances is None:
            self.instances = []

class ZapReportParser:
    """Enhanced parser for ZAP reports and custom scan results"""
    
    def __init__(self, report_data: Dict[str, Any]):
        self.report_data = report_data
        self.vulnerabilities: List[Vulnerability] = []
        self.metadata = {}
        self.summary = {}
        self._parse_report()
    
    def _parse_report(self):
        """Parse the report data based on its format"""
        try:
            if self._is_custom_scan_format():
                self._parse_custom_scan()
            else:
                self._parse_zap_format()
        except Exception as e:
            logger.error(f"Failed to parse report: {e}")
    
    def _is_custom_scan_format(self) -> bool:
        """Check if this is our custom API-based scan format"""
        return 'findings' in self.report_data and 'scan_type' in self.report_data
    
    def _parse_custom_scan(self):
        """Parse custom API-based scan results"""
        logger.info("Parsing custom API-based scan results")
        
        # Extract metadata
        self.metadata = {
            'target_url': self.report_data.get('target', ''),
            'domain': self.report_data.get('domain', ''),
            'scan_timestamp': self.report_data.get('timestamp', ''),
            'scanner': self.report_data.get('scan_type', 'API-based Security Scan'),
            'tool_version': 'AutoPent.AI v1.0'
        }
        
        # Process findings
        findings = self.report_data.get('findings', [])
        
        # Calculate summary statistics
        risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        
        for finding in findings:
            # Convert custom finding to Vulnerability object
            vuln = self._convert_finding_to_vulnerability(finding)
            self.vulnerabilities.append(vuln)
            
            # Update risk counts
            risk = finding.get('severity', 'Low')
            if risk in risk_counts:
                risk_counts[risk] += 1
            else:
                risk_counts['Low'] += 1
        
        # Create summary
        self.summary = {
            'scan_date': self.report_data.get('timestamp', '').split('T')[0] if 'T' in self.report_data.get('timestamp', '') else '',
            'total_alerts': len(findings),
            'risk_counts': risk_counts
        }
        
        logger.info(f"Parsed {len(self.vulnerabilities)} vulnerabilities from custom scan")
    
    def _convert_finding_to_vulnerability(self, finding: Dict) -> Vulnerability:
        """Convert custom finding format to Vulnerability object"""
        # Map severity to risk level
        severity_map = {
            'High': 'High',
            'Medium': 'Medium', 
            'Low': 'Low',
            'Info': 'Informational',
            'Informational': 'Informational'
        }
        
        risk = severity_map.get(finding.get('severity', 'Low'), 'Low')
        
        # Create vulnerability instance
        vuln = Vulnerability(
            name=finding.get('name', 'Unknown Vulnerability'),
            risk=risk,
            confidence='High',  # Default for API-based scans
            url=self.metadata.get('target_url', ''),
            description=finding.get('description', ''),
            solution=finding.get('remediation', ''),
            reference='',
            evidence=finding.get('evidence', ''),
            instances=[{
                'uri': self.metadata.get('target_url', ''),
                'method': 'GET',
                'param': '',
                'attack': '',
                'evidence': finding.get('evidence', '')
            }]
        )
        
        return vuln
    
    def _parse_zap_format(self):
        """Parse traditional ZAP JSON format"""
        logger.info("Parsing ZAP format report")
        
        # Extract metadata
        self.metadata = self.report_data.get('metadata', {})
        
        # Extract summary
        self.summary = self.report_data.get('summary', {})
        
        # Process alerts/vulnerabilities
        alerts = self.report_data.get('alerts', [])
        
        for alert in alerts:
            vuln = Vulnerability(
                name=alert.get('name', 'Unknown'),
                risk=alert.get('risk', 'Low'),
                confidence=alert.get('confidence', 'Medium'),
                url=alert.get('url', ''),
                description=alert.get('description', ''),
                solution=alert.get('solution', ''),
                reference=alert.get('reference', ''),
                cwe_id=alert.get('cweid'),
                wasc_id=alert.get('wascid'),
                param=alert.get('param', ''),
                attack=alert.get('attack', ''),
                evidence=alert.get('evidence', ''),
                method=alert.get('method', 'GET'),
                instances=alert.get('instances', [])
            )
            self.vulnerabilities.append(vuln)
        
        logger.info(f"Parsed {len(self.vulnerabilities)} vulnerabilities from ZAP format")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get vulnerability statistics"""
        risk_distribution = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        
        for vuln in self.vulnerabilities:
            risk = vuln.risk
            if risk in risk_distribution:
                risk_distribution[risk] += 1
        
        # Calculate categories (grouping similar vulnerability types)
        categories = {}
        for vuln in self.vulnerabilities:
            name = vuln.name.lower()
            if 'header' in name:
                categories['security_headers'] = categories.get('security_headers', 0) + 1
            elif 'ssl' in name or 'certificate' in name:
                categories['ssl_tls'] = categories.get('ssl_tls', 0) + 1
            elif 'javascript' in name or 'script' in name:
                categories['content_security'] = categories.get('content_security', 0) + 1
            elif 'admin' in name or 'path' in name:
                categories['access_control'] = categories.get('access_control', 0) + 1
            elif 'csrf' in name.lower() or 'form' in name:
                categories['authentication'] = categories.get('authentication', 0) + 1
            else:
                categories['other'] = categories.get('other', 0) + 1
        
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'risk_distribution': risk_distribution,
            'target_url': self.metadata.get('target_url', ''),
            'scan_date': self.summary.get('scan_date', ''),
            'categories': categories,
            'unique_urls': 1  # For single-URL scans
        }
    
    def export_to_dict(self) -> Dict[str, Any]:
        """Export parsed data to dictionary format"""
        # Get statistics for UI compatibility
        stats = self.get_statistics()
        
        return {
            'metadata': self.metadata,
            'summary': self.summary,
            'alerts': [self._vulnerability_to_dict(vuln) for vuln in self.vulnerabilities],
            'statistics': stats  # Add statistics for UI compatibility
        }
    
    def _vulnerability_to_dict(self, vuln: Vulnerability) -> Dict[str, Any]:
        """Convert Vulnerability object to dictionary"""
        return {
            'name': vuln.name,
            'risk': vuln.risk,
            'confidence': vuln.confidence,
            'url': vuln.url,
            'description': vuln.description,
            'solution': vuln.solution,
            'reference': vuln.reference,
            'cweid': vuln.cwe_id,
            'wascid': vuln.wasc_id,
            'param': vuln.param,
            'attack': vuln.attack,
            'evidence': vuln.evidence,
            'method': vuln.method,
            'instances': vuln.instances
        }

def parse_zap_report(report_path: str) -> Optional[ZapReportParser]:
    """Parse a ZAP report from file path"""
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        return ZapReportParser(report_data)
        
    except FileNotFoundError:
        logger.error(f"Report file not found: {report_path}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in report file: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to parse report: {e}")
        return None

def get_vulnerability_summary(report_path: str) -> Dict:
    """
    Quick function to get vulnerability summary from report
    Returns: Summary dictionary
    """
    parser = parse_zap_report(report_path)
    
    if parser:
        return {
            "total_vulnerabilities": len(parser.vulnerabilities),
            "risk_counts": parser.summary.get("risk_counts", {}),
            "scan_date": parser.summary.get("scan_date", ""),
            "high_risk_vulns": [v.name for v in parser.vulnerabilities if v.risk.lower() == "High"]
        }
    else:
        return {}

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python zap_parser.py <report_path>")
        sys.exit(1)
    
    report_file = sys.argv[1]
    
    # Parse report
    parser = parse_zap_report(report_file)
    
    if parser:
        print(f"✅ Successfully parsed report: {report_file}")
        print(f"📊 Found {len(parser.vulnerabilities)} vulnerabilities")
        
        # Print summary
        stats = parser.get_statistics()
        print("\n📈 Risk Distribution:")
        for risk, count in stats["risk_distribution"].items():
            print(f"  {risk}: {count}")
        
        # Save parsed data
        output_file = parser.export_to_dict()
        if output_file:
            print(f"💾 Parsed data saved to: {output_file}")
    else:
        print(f"❌ Failed to parse report: {report_file}")
        sys.exit(1) 