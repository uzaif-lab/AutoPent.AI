"""
PDF Report Generator Module
Creates professional penetration testing reports
"""
import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from io import BytesIO
import base64

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, 
    PageBreak, Image, KeepTogether
)
from reportlab.platypus.flowables import HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY

from config import config

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PDFReportGenerator:
    """Professional PDF report generator for penetration testing"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.custom_styles = self._create_custom_styles()
        self.story = []
        
    def _create_custom_styles(self) -> Dict:
        """Create custom paragraph styles"""
        styles = {}
        
        # Title style
        styles['CustomTitle'] = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#2c3e50')
        )
        
        # Subtitle style
        styles['CustomSubtitle'] = ParagraphStyle(
            'CustomSubtitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=20,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#34495e')
        )
        
        # Section header style
        styles['SectionHeader'] = ParagraphStyle(
            'SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.HexColor('#2c3e50'),
            borderWidth=1,
            borderColor=colors.HexColor('#3498db'),
            borderPadding=5,
            backColor=colors.HexColor('#ecf0f1')
        )
        
        # Vulnerability header style
        styles['VulnHeader'] = ParagraphStyle(
            'VulnHeader',
            parent=self.styles['Heading3'],
            fontSize=14,
            spaceAfter=10,
            spaceBefore=15,
            textColor=colors.HexColor('#e74c3c')
        )
        
        # Risk style
        styles['RiskHigh'] = ParagraphStyle(
            'RiskHigh',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#e74c3c'),
            fontName='Helvetica-Bold'
        )
        
        styles['RiskMedium'] = ParagraphStyle(
            'RiskMedium',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#f39c12'),
            fontName='Helvetica-Bold'
        )
        
        styles['RiskLow'] = ParagraphStyle(
            'RiskLow',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#27ae60'),
            fontName='Helvetica-Bold'
        )
        
        return styles
    
    def generate_report(self, scan_data: Dict, ai_analyses: Dict, output_path: str) -> bool:
        """Generate complete PDF report"""
        try:
            logger.info(f"Generating PDF report: {output_path}")
            
            # Create PDF document
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build report content
            self.story = []
            
            # Cover page
            self._add_cover_page(scan_data)
            self.story.append(PageBreak())
            
            # Executive summary
            self._add_executive_summary(scan_data, ai_analyses)
            self.story.append(PageBreak())
            
            # Vulnerability summary table
            self._add_vulnerability_summary_table(scan_data)
            self.story.append(PageBreak())
            
            # Skip pie chart - using text-based risk summary instead
            
            # Detailed vulnerability findings
            self._add_detailed_findings(scan_data, ai_analyses)
            
            # Recommendations
            self._add_recommendations(scan_data, ai_analyses)
            
            # Build PDF
            doc.build(self.story)
            
            logger.info(f"PDF report generated successfully: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            return False
    
    def _add_cover_page(self, scan_data: Dict):
        """Add cover page to report"""
        # Title
        self.story.append(Spacer(1, 2*inch))
        self.story.append(Paragraph(config.REPORT_TITLE, self.custom_styles['CustomTitle']))
        
        # Subtitle
        target_url = scan_data.get('metadata', {}).get('target_url', 'Unknown Target')
        self.story.append(Paragraph(f"Target: {target_url}", self.custom_styles['CustomSubtitle']))
        
        # Date and details
        self.story.append(Spacer(1, 1*inch))
        
        scan_date = scan_data.get('summary', {}).get('scan_date', datetime.now().isoformat())
        if 'T' in scan_date:
            scan_date = scan_date.split('T')[0]
        
        details = [
            f"<b>Report Date:</b> {datetime.now().strftime('%Y-%m-%d')}",
            f"<b>Scan Date:</b> {scan_date}",
            f"<b>Report Version:</b> {config.REPORT_VERSION}",
            f"<b>Generated by:</b> {config.REPORT_AUTHOR}",
            "",
            "<b>Classification:</b> CONFIDENTIAL",
            "<b>Distribution:</b> Internal Use Only"
        ]
        
        for detail in details:
            self.story.append(Paragraph(detail, self.styles['Normal']))
            self.story.append(Spacer(1, 6))
        
        # Footer
        self.story.append(Spacer(1, 2*inch))
        footer_text = "This report contains confidential information and should be handled accordingly."
        self.story.append(Paragraph(footer_text, self.styles['BodyText']))
    
    def _add_executive_summary(self, scan_data: Dict, ai_analyses: Dict):
        """Add executive summary section"""
        self.story.append(Paragraph("Executive Summary", self.custom_styles['SectionHeader']))
        
        summary_data = scan_data.get('summary', {})
        risk_counts = summary_data.get('risk_counts', {})
        total_vulns = summary_data.get('total_alerts', 0)
        
        # Summary overview
        summary_text = f"""
        This report presents the findings of an automated web application security assessment 
        conducted using AI-augmented analysis. The assessment identified <b>{total_vulns}</b> 
        potential security vulnerabilities across the target application.
        """
        
        self.story.append(Paragraph(summary_text, self.styles['BodyText']))
        self.story.append(Spacer(1, 12))
        
        # Risk breakdown
        risk_summary = f"""
        <b>Risk Distribution:</b><br/>
        • High Risk: {risk_counts.get('High', 0)} vulnerabilities<br/>
        • Medium Risk: {risk_counts.get('Medium', 0)} vulnerabilities<br/>
        • Low Risk: {risk_counts.get('Low', 0)} vulnerabilities<br/>
        • Informational: {risk_counts.get('Informational', 0)} findings
        """
        
        self.story.append(Paragraph(risk_summary, self.styles['BodyText']))
        self.story.append(Spacer(1, 12))
        
        # Key findings
        high_risk_vulns = [v for v in scan_data.get('vulnerabilities', []) if v.get('risk') == 'High']
        
        if high_risk_vulns:
            key_findings = "<b>Critical Findings:</b><br/>"
            for vuln in high_risk_vulns[:3]:  # Top 3 high-risk vulnerabilities
                key_findings += f"• {vuln.get('name', 'Unknown Vulnerability')}<br/>"
            
            self.story.append(Paragraph(key_findings, self.styles['BodyText']))
            self.story.append(Spacer(1, 12))
        
        # Recommendations summary
        recommendations_text = """
        <b>Immediate Actions Required:</b><br/>
        1. Address all high-risk vulnerabilities within 24-48 hours<br/>
        2. Implement input validation and output encoding<br/>
        3. Review and update security configurations<br/>
        4. Conduct regular security assessments
        """
        
        self.story.append(Paragraph(recommendations_text, self.styles['BodyText']))
    
    def _add_vulnerability_summary_table(self, scan_data: Dict):
        """Add vulnerability summary table"""
        self.story.append(Paragraph("Vulnerability Summary", self.custom_styles['SectionHeader']))
        
        # Check both 'alerts' (from parser) and 'vulnerabilities' (legacy) keys
        vulnerabilities = scan_data.get('alerts', scan_data.get('vulnerabilities', []))
        
        if not vulnerabilities:
            self.story.append(Paragraph("No vulnerabilities were identified during the scan.", self.styles['BodyText']))
            return
        
        # Create table data
        table_data = [['Vulnerability Name', 'Risk Level', 'Confidence', 'URL', 'CWE ID']]
        
        for vuln in vulnerabilities:
            # Truncate long URLs
            url = vuln.get('url', '')
            if len(url) > 40:
                url = url[:37] + '...'
            
            table_data.append([
                vuln.get('name', 'Unknown')[:40],
                vuln.get('risk', 'Unknown'),
                vuln.get('confidence', 'Unknown'),
                url,
                vuln.get('cwe_id', 'N/A')
            ])
        
        # Create table
        table = Table(table_data, colWidths=[2.5*inch, 0.8*inch, 0.8*inch, 2*inch, 0.6*inch])
        
        # Style table
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        # Add risk-based row coloring
        for i, vuln in enumerate(vulnerabilities, 1):
            risk = vuln.get('risk', '').lower()
            if risk == 'high':
                table.setStyle(TableStyle([('BACKGROUND', (1, i), (1, i), colors.HexColor('#ffebee'))]))
            elif risk == 'medium':
                table.setStyle(TableStyle([('BACKGROUND', (1, i), (1, i), colors.HexColor('#fff3e0'))]))
            elif risk == 'low':
                table.setStyle(TableStyle([('BACKGROUND', (1, i), (1, i), colors.HexColor('#e8f5e8'))]))
        
        self.story.append(table)
    
    # Removed pie chart functionality - using text-based risk summaries instead
    
    def _add_detailed_findings(self, scan_data: Dict, ai_analyses: Dict):
        """Add detailed vulnerability findings"""
        self.story.append(Paragraph("Detailed Findings", self.custom_styles['SectionHeader']))
        
        # Check both 'alerts' (from parser) and 'vulnerabilities' (legacy) keys
        vulnerabilities = scan_data.get('alerts', scan_data.get('vulnerabilities', []))
        
        if not vulnerabilities:
            self.story.append(Paragraph("No detailed findings available.", self.styles['BodyText']))
            return
        
        # Sort vulnerabilities by risk (High -> Medium -> Low -> Info)
        risk_order = {'High': 0, 'Medium': 1, 'Low': 2, 'Informational': 3}
        sorted_vulns = sorted(vulnerabilities, key=lambda x: risk_order.get(x.get('risk', 'Informational'), 3))
        
        for i, vuln in enumerate(sorted_vulns):
            if i > 0:
                self.story.append(Spacer(1, 20))
            
            ai_analysis = ai_analyses.get(vuln.get('name', ''))
            self._add_vulnerability_detail(vuln, ai_analysis)
    
    def _add_vulnerability_detail(self, vuln: Dict, ai_analysis: Dict):
        """Add detailed vulnerability information"""
        vuln_name = vuln.get('name', 'Unknown Vulnerability')
        risk_level = vuln.get('risk', 'Unknown')
        
        # Vulnerability header
        header_text = f"{vuln_name} [{risk_level} Risk]"
        self.story.append(Paragraph(header_text, self.custom_styles['VulnHeader']))
        
        # Basic information table
        basic_info = [
            ['Property', 'Value'],
            ['Risk Level', risk_level],
            ['Confidence', vuln.get('confidence', 'Unknown')],
            ['CWE ID', vuln.get('cwe_id', 'Not specified')],
            ['Affected URL', vuln.get('url', 'Not specified')],
            ['Parameter', vuln.get('param', 'Not specified')]
        ]
        
        info_table = Table(basic_info, colWidths=[1.5*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        self.story.append(info_table)
        self.story.append(Spacer(1, 12))
        
        # AI Analysis (if available)
        if ai_analysis:
            self._add_ai_analysis_section(ai_analysis)
        else:
            # Fallback description and solution
            description = vuln.get('description', 'No description available.')
            self.story.append(Paragraph(f"<b>Description:</b> {description}", self.styles['BodyText']))
            self.story.append(Spacer(1, 6))
            
            # Evidence section
            evidence = vuln.get('evidence', '')
            if evidence:
                self.story.append(Paragraph(f"<b>Evidence:</b> {evidence}", self.styles['BodyText']))
                self.story.append(Spacer(1, 6))
            
            # Solution/Remediation section
            solution = vuln.get('solution', vuln.get('remediation', 'No solution provided.'))
            self.story.append(Paragraph(f"<b>Remediation:</b> {solution}", self.styles['BodyText']))
            self.story.append(Spacer(1, 6))
            
            # Instance details
            instances = vuln.get('instances', [])
            if instances:
                self.story.append(Paragraph("<b>Affected Locations:</b>", self.styles['BodyText']))
                for instance in instances[:3]:  # Show up to 3 instances
                    uri = instance.get('uri', instance.get('url', ''))
                    if uri:
                        self.story.append(Paragraph(f"• {uri}", self.styles['BodyText']))
                self.story.append(Spacer(1, 6))
    
    def _add_ai_analysis_section(self, ai_analysis):
        """Add AI analysis section"""
        # Handle both dict and AIAnalysis object
        if hasattr(ai_analysis, 'explanation'):
            # AIAnalysis object
            sections = [
                ('Description', ai_analysis.explanation or ''),
                ('Impact', ai_analysis.impact or ''),
                ('Remediation', ai_analysis.remediation or ''),
                ('Prevention', ai_analysis.prevention or '')
            ]
        else:
            # Dictionary
            sections = [
                ('Description', ai_analysis.get('explanation', '')),
                ('Impact', ai_analysis.get('impact', '')),
                ('Remediation', ai_analysis.get('remediation', '')),
                ('Prevention', ai_analysis.get('prevention', ''))
            ]
        
        for title, content in sections:
            if content:
                self.story.append(Paragraph(f"<b>{title}:</b>", self.styles['BodyText']))
                self.story.append(Paragraph(content, self.styles['BodyText']))
                self.story.append(Spacer(1, 6))
    
    def _add_recommendations(self, scan_data: Dict, ai_analyses: Dict):
        """Add recommendations section"""
        self.story.append(PageBreak())
        self.story.append(Paragraph("Recommendations", self.custom_styles['SectionHeader']))
        
        # General recommendations
        general_recs = [
            "Implement a comprehensive input validation framework",
            "Deploy proper output encoding mechanisms",
            "Enable security headers (CSP, HSTS, X-Frame-Options)",
            "Conduct regular security code reviews", 
            "Implement automated security testing in CI/CD pipeline",
            "Establish an incident response plan",
            "Provide security training for development team"
        ]
        
        self.story.append(Paragraph("<b>General Security Recommendations:</b>", self.styles['BodyText']))
        self.story.append(Spacer(1, 6))
        
        for i, rec in enumerate(general_recs, 1):
            self.story.append(Paragraph(f"{i}. {rec}", self.styles['BodyText']))
            self.story.append(Spacer(1, 3))
        
        self.story.append(Spacer(1, 12))
        
        # Risk-based remediation timeline
        timeline_text = """
        <b>Recommended Remediation Timeline:</b><br/>
        • <b>Critical/High Risk:</b> Immediate action required (24-48 hours)<br/>
        • <b>Medium Risk:</b> Address within 1-2 weeks<br/>
        • <b>Low Risk:</b> Include in next maintenance cycle<br/>
        • <b>Informational:</b> Monitor and review during next assessment
        """
        
        self.story.append(Paragraph(timeline_text, self.styles['BodyText']))

def generate_pentest_report(scan_data: Dict, ai_analyses: Dict, target_url: str) -> str:
    """
    Generate complete penetration testing report
    Returns: Path to generated PDF file
    """
    try:
        # Generate filename
        from urllib.parse import urlparse
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc.replace(':', '_').replace('.', '_')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Determine scan type from scan data
        scan_type = scan_data.get('scan_type', '')
        if 'API-based' in scan_type:
            filename = f"pentest_report_API_based_{domain}_{timestamp}.pdf"
        else:
            filename = f"pentest_report_{domain}_{timestamp}.pdf"
        
        output_path = config.REPORTS_DIR / filename
        
        # Generate report
        generator = PDFReportGenerator()
        success = generator.generate_report(scan_data, ai_analyses, str(output_path))
        
        if success:
            logger.info(f"Report generated successfully: {output_path}")
            return str(output_path)
        else:
            logger.error("Failed to generate report")
            return ""
            
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return ""

if __name__ == "__main__":
    # Test report generation
    print("📄 Testing PDF report generation...")
    
    # Sample data
    test_scan_data = {
        'metadata': {'target_url': 'https://example.com'},
        'summary': {
            'scan_date': '2024-01-15',
            'total_alerts': 5,
            'risk_counts': {'High': 2, 'Medium': 2, 'Low': 1, 'Informational': 0}
        },
        'vulnerabilities': [
            {
                'name': 'Cross-Site Scripting (XSS)',
                'risk': 'High',
                'confidence': 'High',
                'url': 'https://example.com/search?q=test',
                'cwe_id': '79',
                'description': 'XSS vulnerability detected'
            }
        ]
    }
    
    test_ai_analyses = {
        'Cross-Site Scripting (XSS)': {
            'explanation': 'This is a reflected XSS vulnerability...',
            'impact': 'Could lead to session hijacking...',
            'remediation': 'Implement proper input validation...',
            'prevention': 'Use CSP headers and output encoding...'
        }
    }
    
    report_path = generate_pentest_report(test_scan_data, test_ai_analyses, 'https://example.com')
    
    if report_path:
        print(f"✅ Test report generated: {report_path}")
    else:
        print("❌ Report generation failed") 