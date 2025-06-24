#!/usr/bin/env python3
"""
AI-Augmented Web Pentesting Assistant
Main orchestrator that coordinates scanning, analysis, and reporting
"""
import sys
import argparse
import logging
from pathlib import Path
from typing import Dict, Tuple
import time
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

# Import our modules
from config import config
from scanner.run_zap_scan import scan_website
from parser.zap_parser import parse_zap_report
from ai_module.summarize import analyze_vulnerabilities
from cvss.calculate import VulnerabilityRiskAssessment
from report.generate_pdf import generate_pentest_report

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('autopent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Rich console for beautiful output
console = Console()

class AutoPentAssistant:
    """Main class for the AI-Augmented Pentesting Assistant"""
    
    def __init__(self):
        self.scan_report_path = ""
        self.parsed_data = None
        self.ai_analyses = {}
        self.risk_assessments = {}
        self.final_report_path = ""
        
    def run_full_assessment(self, target_url: str, skip_scan: bool = False, 
                          scan_report_path: str = None) -> Tuple[bool, str]:
        """
        Run complete security assessment workflow
        
        Args:
            target_url: Target URL to scan
            skip_scan: Skip scanning and use existing report
            scan_report_path: Path to existing scan report (if skip_scan=True)
            
        Returns:
            Tuple of (success, report_path_or_error)
        """
        try:
            console.print(Panel.fit(
                f"🔒 AI-Augmented Web Application Security Assessment\n"
                f"Target: {target_url}",
                border_style="blue"
            ))
            
            # Step 1: Vulnerability Scanning
            if not skip_scan:
                success = self._perform_vulnerability_scan(target_url)
                if not success:
                    return False, "Vulnerability scanning failed"
            else:
                self.scan_report_path = scan_report_path
                console.print("📂 Using existing scan report", style="yellow")
            
            # Step 2: Parse Scan Results
            success = self._parse_scan_results()
            if not success:
                return False, "Failed to parse scan results"
            
            # Step 3: AI Analysis
            success = self._perform_ai_analysis()
            if not success:
                console.print("⚠️  AI analysis failed, continuing with basic analysis", style="yellow")
            
            # Step 4: Risk Assessment
            self._perform_risk_assessment()
            
            # Step 5: Generate Report
            success = self._generate_final_report(target_url)
            if not success:
                return False, "Failed to generate final report"
            
            # Step 6: Display Summary
            self._display_assessment_summary()
            
            return True, self.final_report_path
            
        except KeyboardInterrupt:
            console.print("\n❌ Assessment interrupted by user", style="red")
            return False, "Assessment interrupted"
        except Exception as e:
            logger.error(f"Assessment failed: {e}")
            console.print(f"❌ Assessment failed: {e}", style="red")
            return False, str(e)
    
    def _perform_vulnerability_scan(self, target_url: str) -> bool:
        """Perform vulnerability scanning using API-based scanner"""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                scan_task = progress.add_task("🕷️  Scanning for vulnerabilities...", total=None)
                
                # Use the new API-based scanner
                scan_results = scan_website(target_url)
                
                if scan_results and 'findings' in scan_results:
                    # Save results to a temporary file for compatibility
                    import tempfile
                    import json
                    from datetime import datetime
                    
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    report_filename = f"scan_results_{timestamp}.json"
                    scan_dir = Path("scans")
                    scan_dir.mkdir(exist_ok=True)
                    
                    self.scan_report_path = scan_dir / report_filename
                    
                    with open(self.scan_report_path, 'w') as f:
                        json.dump(scan_results, f, indent=2)
                    
                    progress.update(scan_task, description="✅ Vulnerability scan completed")
                    console.print(f"📄 Scan report saved: {self.scan_report_path}", style="green")
                    return True
                else:
                    progress.update(scan_task, description="❌ Vulnerability scan failed")
                    console.print("❌ Scan failed: No results returned", style="red")
                    return False
                    
        except Exception as e:
            logger.error(f"Vulnerability scan failed: {e}")
            console.print(f"❌ Scan error: {e}", style="red")
            return False
    
    def _parse_scan_results(self) -> bool:
        """Parse scan results from ZAP report"""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                parse_task = progress.add_task("📊 Parsing scan results...", total=None)
                
                parser = parse_zap_report(self.scan_report_path)
                
                if parser:
                    self.parsed_data = parser.export_to_dict()
                    progress.update(parse_task, description="✅ Scan results parsed")
                    
                    vulns_count = len(parser.vulnerabilities)
                    console.print(f"📈 Found {vulns_count} vulnerabilities", style="cyan")
                    
                    # Display quick stats
                    stats = parser.get_statistics()
                    risk_dist = stats['risk_distribution']
                    
                    stats_table = Table(title="Risk Distribution")
                    stats_table.add_column("Risk Level", style="bold")
                    stats_table.add_column("Count", justify="center")
                    
                    for risk, count in risk_dist.items():
                        if count > 0:
                            color = self._get_risk_color(risk)
                            stats_table.add_row(risk, str(count), style=color)
                    
                    console.print(stats_table)
                    return True
                else:
                    progress.update(parse_task, description="❌ Failed to parse results")
                    console.print("❌ Failed to parse scan results", style="red")
                    return False
                    
        except Exception as e:
            logger.error(f"Parse failed: {e}")
            console.print(f"❌ Parse error: {e}", style="red")
            return False
    
    def _perform_ai_analysis(self) -> bool:
        """Perform AI analysis of vulnerabilities"""
        try:
            vulnerabilities = [
                type('Vulnerability', (), vuln)() 
                for vuln in self.parsed_data.get('vulnerabilities', [])
            ]
            
            if not vulnerabilities:
                console.print("ℹ️  No vulnerabilities to analyze", style="yellow")
                return True
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                ai_task = progress.add_task("🤖 Performing AI analysis...", total=len(vulnerabilities))
                
                # Check if OpenAI is configured
                if not config.OPENAI_API_KEY:
                    progress.update(ai_task, description="⚠️  OpenAI API key not configured")
                    console.print("⚠️  OpenAI API key not configured. Using fallback analysis.", style="yellow")
                    return False
                
                self.ai_analyses = analyze_vulnerabilities(vulnerabilities)
                
                progress.update(ai_task, completed=len(vulnerabilities), 
                              description="✅ AI analysis completed")
                
                console.print(f"🧠 AI analyzed {len(self.ai_analyses)} vulnerabilities", style="green")
                return True
                
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            console.print(f"⚠️  AI analysis error: {e}", style="yellow")
            return False
    
    def _perform_risk_assessment(self):
        """Perform CVSS risk assessment"""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                risk_task = progress.add_task("📊 Calculating risk scores...", total=None)
                
                risk_assessor = VulnerabilityRiskAssessment()
                
                for vuln in self.parsed_data.get('vulnerabilities', []):
                    vuln_name = vuln.get('name', '')
                    assessment = risk_assessor.assess_vulnerability_risk(vuln_name, vuln)
                    self.risk_assessments[vuln_name] = assessment
                
                progress.update(risk_task, description="✅ Risk assessment completed")
                console.print(f"📋 Risk assessed for {len(self.risk_assessments)} vulnerabilities", style="green")
                
        except Exception as e:
            logger.error(f"Risk assessment failed: {e}")
            console.print(f"⚠️  Risk assessment error: {e}", style="yellow")
    
    def _generate_final_report(self, target_url: str) -> bool:
        """Generate final PDF report"""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                report_task = progress.add_task("📄 Generating PDF report...", total=None)
                
                report_path = generate_pentest_report(
                    self.parsed_data, 
                    self.ai_analyses, 
                    target_url
                )
                
                if report_path:
                    self.final_report_path = report_path
                    progress.update(report_task, description="✅ PDF report generated")
                    console.print(f"📋 Report saved: {report_path}", style="green")
                    return True
                else:
                    progress.update(report_task, description="❌ Report generation failed")
                    return False
                    
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            console.print(f"❌ Report error: {e}", style="red")
            return False
    
    def _display_assessment_summary(self):
        """Display final assessment summary"""
        try:
            summary_table = Table(title="🔒 Security Assessment Summary", border_style="blue")
            summary_table.add_column("Metric", style="bold")
            summary_table.add_column("Value", justify="center")
            
            # Basic stats
            total_vulns = len(self.parsed_data.get('vulnerabilities', []))
            summary_table.add_row("Total Vulnerabilities", str(total_vulns))
            
            # Risk distribution
            stats = self.parsed_data.get('statistics', {})
            risk_dist = stats.get('risk_distribution', {})
            
            for risk, count in risk_dist.items():
                if count > 0:
                    color = self._get_risk_color(risk)
                    summary_table.add_row(f"{risk} Risk", str(count), style=color)
            
            summary_table.add_row("AI Analyses", str(len(self.ai_analyses)))
            summary_table.add_row("Risk Assessments", str(len(self.risk_assessments)))
            summary_table.add_row("Final Report", Path(self.final_report_path).name if self.final_report_path else "Not generated")
            
            console.print(summary_table)
            
            # Success message
            console.print(Panel.fit(
                "✅ Assessment completed successfully!\n"
                f"📊 Found {total_vulns} vulnerabilities\n"
                f"📄 Report: {Path(self.final_report_path).name if self.final_report_path else 'Not available'}",
                border_style="green",
                title="Assessment Complete"
            ))
            
        except Exception as e:
            logger.error(f"Failed to display summary: {e}")
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level"""
        colors = {
            'High': 'red',
            'Medium': 'yellow', 
            'Low': 'green',
            'Informational': 'cyan'
        }
        return colors.get(risk_level, 'white')

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='AI-Augmented Web Pentesting Assistant')
    parser.add_argument('--url', '-u', required=True, help='Target URL to scan')
    parser.add_argument('--skip-scan', action='store_true', help='Skip scanning and use existing report')
    parser.add_argument('--scan-report', '-r', help='Path to existing scan report (use with --skip-scan)')
    parser.add_argument('--output-dir', '-o', help='Output directory for reports')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate arguments
    if args.skip_scan and not args.scan_report:
        console.print("❌ --scan-report is required when using --skip-scan", style="red")
        sys.exit(1)
    
    if args.skip_scan and not Path(args.scan_report).exists():
        console.print(f"❌ Scan report not found: {args.scan_report}", style="red")
        sys.exit(1)
    
    # Set output directory
    if args.output_dir:
        config.REPORTS_DIR = Path(args.output_dir)
        config.REPORTS_DIR.mkdir(exist_ok=True)
    
    # Print banner
    console.print(Panel.fit(
        "🤖 AutoPent.AI - AI-Augmented Web Pentesting Assistant\n"
        "Automated vulnerability scanning with intelligent analysis",
        border_style="cyan",
        title="Welcome"
    ))
    
    # Run assessment
    assistant = AutoPentAssistant()
    
    start_time = time.time()
    success, result = assistant.run_full_assessment(
        target_url=args.url,
        skip_scan=args.skip_scan,
        scan_report_path=args.scan_report
    )
    
    elapsed_time = time.time() - start_time
    
    if success:
        console.print(f"\n🎉 Assessment completed in {elapsed_time:.1f} seconds", style="bold green")
        console.print(f"📋 Final report: {result}", style="cyan")
        sys.exit(0)
    else:
        console.print(f"\n💥 Assessment failed: {result}", style="bold red")
        sys.exit(1)

if __name__ == "__main__":
    main() 