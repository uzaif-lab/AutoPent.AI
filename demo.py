#!/usr/bin/env python3
"""
Demo script for AutoPent.AI - Test with sample data
"""
import sys
from pathlib import Path
import json

# Add project root to path
sys.path.append(str(Path(__file__).parent))

from parser.zap_parser import parse_zap_report
from ai_module.summarize import analyze_single_vulnerability
from cvss.calculate import VulnerabilityRiskAssessment
from report.generate_pdf import generate_pentest_report
from config import config

def main():
    """Run demo with sample data"""
    print("🤖 AutoPent.AI Demo")
    print("=" * 50)
    
    # Use sample report
    sample_report = Path("sample_outputs/example_report.json")
    
    if not sample_report.exists():
        print("❌ Sample report not found")
        return
    
    print(f"📄 Using sample report: {sample_report}")
    
    # Test parser
    print("\n1️⃣ Testing Report Parser...")
    parser = parse_zap_report(str(sample_report))
    
    if parser:
        print(f"✅ Parsed {len(parser.vulnerabilities)} vulnerabilities")
        
        # Show vulnerability summary
        stats = parser.get_statistics()
        print("\n📊 Vulnerability Summary:")
        for risk, count in stats['risk_distribution'].items():
            if count > 0:
                print(f"  {risk}: {count}")
    else:
        print("❌ Parser failed")
        return
    
    # Test AI analysis (if API key is available)
    print("\n2️⃣ Testing AI Analysis...")
    if config.OPENAI_API_KEY:
        if parser.vulnerabilities:
            test_vuln = parser.vulnerabilities[0]
            analysis = analyze_single_vulnerability(test_vuln)
            
            if analysis:
                print(f"✅ AI analysis for: {analysis.vulnerability_name}")
                print(f"   Explanation: {analysis.explanation[:100]}...")
            else:
                print("❌ AI analysis failed")
    else:
        print("⚠️  OpenAI API key not configured - skipping AI analysis")
    
    # Test CVSS calculation
    print("\n3️⃣ Testing CVSS Calculation...")
    risk_assessor = VulnerabilityRiskAssessment()
    
    if parser.vulnerabilities:
        test_vuln_data = parser.vulnerabilities[0].to_dict()
        assessment = risk_assessor.assess_vulnerability_risk(
            test_vuln_data['name'], 
            test_vuln_data
        )
        
        cvss_score = assessment['cvss_score']['base_score']
        print(f"✅ CVSS Score calculated: {cvss_score}")
    
    # Test report generation
    print("\n4️⃣ Testing PDF Report Generation...")
    try:
        scan_data = parser.export_to_dict()
        ai_analyses = {}  # Empty for demo
        
        report_path = generate_pentest_report(
            scan_data, 
            ai_analyses, 
            "https://example.com"
        )
        
        if report_path:
            print(f"✅ PDF report generated: {Path(report_path).name}")
        else:
            print("❌ Report generation failed")
    except Exception as e:
        print(f"❌ Report generation error: {e}")
    
    print("\n🎉 Demo completed!")
    print("\nNext steps:")
    print("1. Add your OpenAI API key to .env file")
    print("2. Install OWASP ZAP for real scanning")
    print("3. Run: python main.py --url https://your-target.com")
    print("4. Or start web UI: python run_streamlit.py")

if __name__ == "__main__":
    main() 