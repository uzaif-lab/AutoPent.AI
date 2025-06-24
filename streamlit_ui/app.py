"""
Streamlit Web Interface for AI-Augmented Pentesting Assistant
Provides a user-friendly web interface for security assessments
"""
import streamlit as st
import pandas as pd
# Removed plotly imports - using simple metrics instead of charts
import time
import json
from pathlib import Path
from datetime import datetime
import base64
from io import BytesIO
import sys
import os
from typing import Dict, List, Optional

# Add parent directory to path to import our modules
sys.path.append(str(Path(__file__).parent.parent))

# Ensure we load environment variables properly in Streamlit context
import os
from dotenv import load_dotenv

# Load .env file from the parent directory
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

from config import config
from parser.zap_parser import parse_zap_report

# Import components directly to avoid main.py import issues
from scanner.run_zap_scan import scan_website
from ai_module.summarize import VulnerabilityAnalyzer
from report.generate_pdf import generate_pentest_report

# Page configuration
st.set_page_config(
    page_title="AutoPent.AI - Security Assistant",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)



# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #667eea;
        margin: 0.5rem 0;
    }
    .risk-high { border-left-color: #dc3545 !important; }
    .risk-medium { border-left-color: #ffc107 !important; }
    .risk-low { border-left-color: #28a745 !important; }
    .risk-info { border-left-color: #17a2b8 !important; }
    .stButton > button {
        width: 100%;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.5rem 1rem;
    }
</style>
""", unsafe_allow_html=True)

class StreamlitPentestUI:
    """Streamlit UI for the pentesting assistant"""
    
    def __init__(self):
        # Initialize components directly
        self.vulnerability_analyzer = VulnerabilityAnalyzer()
        self.parsed_data = None
        
    def run(self):
        """Main UI entry point"""
        # Header
        st.markdown("""
        <div class="main-header">
            <h1>🤖 AutoPent.AI</h1>
            <h3>AI-Augmented Web Application Security Assistant</h3>
            <p>Automated vulnerability scanning with intelligent analysis</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Sidebar
        self._render_sidebar()
        
        # Main content based on selected tab
        tab = st.session_state.get('selected_tab', 'scanner')
        
        if tab == 'scanner':
            self._render_scanner_tab()
        elif tab == 'reports':
            self._render_reports_tab()
        elif tab == 'analytics':
            self._render_analytics_tab()
        elif tab == 'settings':
            self._render_settings_tab()
    
    def _render_sidebar(self):
        """Render sidebar navigation"""
        with st.sidebar:
            st.image("https://via.placeholder.com/200x80/667eea/white?text=AutoPent.AI", 
                    use_column_width=True)
            
            st.markdown("### 🧭 Navigation")
            
            tabs = {
                'scanner': '🕷️ Security Scanner',
                'reports': '📊 Reports',
                'analytics': '📈 Analytics', 
                'settings': '⚙️ Settings'
            }
            
            for key, label in tabs.items():
                if st.button(label, key=f"nav_{key}"):
                    st.session_state.selected_tab = key
                    st.rerun()
            
            st.markdown("---")
            
            # Quick stats if available
            if 'last_scan_results' in st.session_state:
                self._render_quick_stats()
            
            st.markdown("---")
            st.markdown("### 📚 Resources")
            st.markdown("- [OWASP Top 10](https://owasp.org/www-project-top-ten/)")
            st.markdown("- [CWE Database](https://cwe.mitre.org/)")
            st.markdown("- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)")
    
    def _render_scanner_tab(self):
        """Render the main scanner interface"""
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("## 🕷️ Vulnerability Scanner")
            
            # Scan configuration
            with st.form("scan_form"):
                st.markdown("### 🎯 Target Configuration")
                
                target_url = st.text_input(
                    "Target URL",
                    placeholder="https://example.com",
                    help="Enter the URL of the web application to scan"
                )
                
                col_scan1, col_scan2 = st.columns(2)
                
                with col_scan1:
                    scan_type = st.selectbox(
                        "Scan Type",
                        ["Quick Scan", "Deep Scan", "Custom"],
                        help="Choose scan intensity"
                    )
                
                with col_scan2:
                    # Check if OpenAI is available
                    ai_available = bool(config.OPENAI_API_KEY)
                    include_ai = st.checkbox(
                        "AI Analysis",
                        value=ai_available,  # Enable by default only if API key is available
                        disabled=not ai_available,  # Disable if no API key
                        help="Enable AI-powered vulnerability analysis" if ai_available else "OpenAI API key required for AI analysis"
                    )
                    
                    if ai_available:
                        st.success("🤖 AI analysis available")
                    else:
                        st.error("❌ AI analysis unavailable")
                
                # Scan Information
                with st.expander("ℹ️ Scan Information"):
                    st.markdown("**This scan will analyze:**")
                    st.markdown("✅ HTTP Security Headers")
                    st.markdown("✅ SSL/TLS Configuration") 
                    st.markdown("✅ Domain Information")
                    st.markdown("✅ Content Security")
                    st.markdown("✅ Common Vulnerabilities")
                    
                    if ai_available:
                        st.markdown("🤖 **AI Analysis includes:**")
                        st.markdown("• Vulnerability explanations")
                        st.markdown("• Impact assessments") 
                        st.markdown("• Remediation recommendations")
                
                # Scan button
                submitted = st.form_submit_button("🚀 Start Security Scan", type="primary")
                
                if submitted:
                    if not target_url:
                        st.error("Please enter a target URL")
                    else:
                        self._run_security_scan(target_url, include_ai, scan_type)
        
        with col2:
            st.markdown("### 📋 Scan Status")
            
            # Current scan status
            if 'scan_in_progress' in st.session_state:
                self._render_scan_progress()
            else:
                st.info("Ready to scan. Configure your target and click 'Start Security Scan'.")
            
            # Recent scans
            self._render_recent_scans()
    
    def _render_reports_tab(self):
        """Render reports management tab"""
        st.markdown("## 📊 Security Reports")
        
        # Report filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            date_filter = st.date_input("Filter by Date")
        with col2:
            risk_filter = st.selectbox("Risk Level", ["All", "High", "Medium", "Low"])
        with col3:
            format_filter = st.selectbox("Format", ["All", "PDF", "JSON", "CSV"])
        
        # Reports list
        reports = self._get_available_reports()
        
        if reports:
            st.markdown("### 📄 Available Reports")
            
            for report in reports:
                with st.expander(f"📋 {report['name']} - {report['date']}"):
                    col_rep1, col_rep2, col_rep3 = st.columns(3)
                    
                    with col_rep1:
                        st.metric("Vulnerabilities", report['vuln_count'])
                    with col_rep2:
                        st.metric("High Risk", report['high_risk'])
                    with col_rep3:
                        st.metric("Score", f"{report['score']}/10")
                    
                    col_btn1, col_btn2, col_btn3 = st.columns(3)
                    
                    with col_btn1:
                        if st.button("📥 Download", key=f"download_{report['id']}"):
                            self._download_report(report['path'])
                    
                    with col_btn2:
                        if st.button("👁️ View", key=f"view_{report['id']}"):
                            self._view_report(report['path'])
                    
                    with col_btn3:
                        if st.button("🗑️ Delete", key=f"delete_{report['id']}"):
                            self._delete_report(report['path'])
        else:
            st.info("No reports available. Run a security scan to generate reports.")
    
    def _render_analytics_tab(self):
        """Render analytics dashboard"""
        st.markdown("## 📈 Security Analytics")
        
        if 'last_scan_results' not in st.session_state:
            st.info("No scan data available. Please run a security scan first.")
            return
        
        scan_data = st.session_state.last_scan_results
        
        # Key metrics
        self._render_key_metrics(scan_data)
        
        # Risk Distribution Summary
        self._render_risk_summary_table(scan_data)
        
        # Vulnerability Trends Chart
        self._render_vulnerability_trends_chart(scan_data)
        
        # Detailed analysis
        self._render_vulnerability_details(scan_data)
    
    def _render_settings_tab(self):
        """Render settings configuration"""
        st.markdown("## ⚙️ Settings")
        
        # System Status
        with st.expander("🔑 System Status", expanded=True):
            # OpenAI Status
            if config.OPENAI_API_KEY:
                st.success("✅ OpenAI AI analysis enabled")
                
                # Test OpenAI connection
                if st.button("🧪 Test OpenAI Connection"):
                    try:
                        analyzer = VulnerabilityAnalyzer()
                        if analyzer.initialize_openai():
                            st.success("✅ OpenAI connection successful!")
                        else:
                            st.error("❌ OpenAI connection failed")
                    except Exception as e:
                        st.error(f"❌ OpenAI test failed: {e}")
            else:
                st.error("❌ OpenAI AI analysis disabled - contact administrator")
            
            # Scanner Status
            st.info("✅ API-based security scanner ready")
            st.info("✅ PDF report generation enabled")
        
        # Scan Configuration  
        with st.expander("🕷️ Scan Settings"):
            st.info("📡 Using API-based security scanning")
            st.markdown("**Scan Features:**")
            st.markdown("- HTTP Security Headers Analysis")
            st.markdown("- SSL/TLS Certificate Validation") 
            st.markdown("- Domain Information Gathering")
            st.markdown("- Content Security Analysis")
            st.markdown("- Common Vulnerability Detection")
        
        # Report Configuration
        with st.expander("📄 Report Settings"):
            report_author = st.text_input("Report Author", value=config.REPORT_AUTHOR)
            report_title = st.text_input("Report Title", value=config.REPORT_TITLE)
        
        # System Information
        with st.expander("ℹ️ System Information"):
            st.markdown(f"**Python Version:** {sys.version}")
            st.markdown(f"**Streamlit Version:** {st.__version__}")
            st.markdown(f"**Config Directory:** {config.PROJECT_ROOT}")
    
    def _run_security_scan(self, target_url: str, include_ai: bool, scan_type: str):
        """Execute security scan with progress tracking"""
        # Initialize scan progress
        st.session_state.scan_in_progress = True
        st.session_state.scan_progress = 0
        st.session_state.scan_status = "Initializing scan..."
        
        # Progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        try:
            # Step 1: Vulnerability Scan
            progress_bar.progress(20)
            status_text.text("🕷️ Starting vulnerability scan...")
            
            scan_data = scan_website(target_url)
            if not scan_data or not scan_data.get('findings'):
                st.error("Scan failed - no data returned")
                return
            
            # Step 2: Save scan results
            progress_bar.progress(40)
            status_text.text("💾 Saving scan results...")
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            scan_file = f"scans/scan_results_{timestamp}.json"
            
            # Ensure scans directory exists
            os.makedirs("scans", exist_ok=True)
            
            with open(scan_file, 'w') as f:
                json.dump(scan_data, f, indent=2, default=str)
            
            # Step 3: Parse results
            progress_bar.progress(60)
            status_text.text("📊 Parsing scan results...")
            
            parser = parse_zap_report(scan_file)
            if not parser:
                st.error("Failed to parse scan results")
                return
            
            self.parsed_data = parser
            
            # Step 4: AI Analysis (if enabled and configured)
            ai_analyses = {}
            if include_ai and config.OPENAI_API_KEY:
                progress_bar.progress(70)
                status_text.text("🤖 Performing AI analysis...")
                
                try:
                    if self.vulnerability_analyzer.initialize_openai():
                        st.info(f"🤖 Starting AI analysis of {len(parser.vulnerabilities)} vulnerabilities...")
                        ai_analyses = self.vulnerability_analyzer.analyze_vulnerabilities_batch(parser.vulnerabilities)
                        st.success(f"🧠 AI analyzed {len(ai_analyses)} vulnerabilities")
                    else:
                        st.warning("⚠️ OpenAI connection failed, skipping AI analysis")
                except Exception as e:
                    st.error(f"❌ AI analysis failed: {str(e)}")
                    st.exception(e)
            elif include_ai and not config.OPENAI_API_KEY:
                st.warning("⚠️ OpenAI API key not configured, skipping AI analysis")
            elif not include_ai:
                st.info("ℹ️ AI analysis disabled by user")
            
            # Step 5: Generate PDF report
            progress_bar.progress(90)
            status_text.text("📄 Generating PDF report...")
            
            report_path = generate_pentest_report(scan_data, ai_analyses, target_url)
            
            # Step 6: Complete
            progress_bar.progress(100)
            status_text.text("✅ Scan completed successfully!")
            
            # Store results
            st.session_state.last_scan_results = parser.export_to_dict()
            st.session_state.last_scan_target = target_url
            st.session_state.last_scan_time = datetime.now().isoformat()
            st.session_state.last_scan_report = report_path
            
            st.success(f"Security assessment completed! Report saved: {Path(report_path).name}")
            
            # Auto-switch to analytics tab
            st.session_state.selected_tab = 'analytics'
            time.sleep(2)
            st.rerun()
                
        except Exception as e:
            progress_bar.progress(0)
            status_text.text("❌ Scan error")
            st.error(f"Scan error: {str(e)}")
            st.exception(e)  # Show full traceback for debugging
        
        finally:
            st.session_state.scan_in_progress = False
    
    def _render_scan_progress(self):
        """Render scan progress information"""
        if st.session_state.get('scan_in_progress'):
            st.markdown("### 🔄 Scan in Progress")
            
            progress = st.session_state.get('scan_progress', 0)
            status = st.session_state.get('scan_status', 'Scanning...')
            
            st.progress(progress / 100)
            st.text(status)
            
            if st.button("⏹️ Stop Scan"):
                st.session_state.scan_in_progress = False
                st.warning("Scan stopped by user")
    
    def _render_quick_stats(self):
        """Render quick statistics in sidebar"""
        if 'last_scan_results' in st.session_state:
            data = st.session_state.last_scan_results
            stats = data.get('statistics', {})
            risk_dist = stats.get('risk_distribution', {})
            
            st.markdown("### 📊 Last Scan")
            st.metric("Total Issues", stats.get('total_vulnerabilities', 0))
            
            for risk, count in risk_dist.items():
                if count > 0:
                    color = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢', 'Informational': '🔵'}.get(risk, '⚪')
                    st.metric(f"{color} {risk}", count)
    
    def _render_recent_scans(self):
        """Render recent scans list"""
        st.markdown("### 📚 Recent Scans")
        
        # Mock recent scans (in real app, load from database)
        recent_scans = [
            {"target": "example.com", "date": "2024-01-15", "vulns": 5},
            {"target": "test.com", "date": "2024-01-14", "vulns": 2},
        ]
        
        if recent_scans:
            for scan in recent_scans:
                st.markdown(f"**{scan['target']}**")
                st.markdown(f"Date: {scan['date']}")
                st.markdown(f"Issues: {scan['vulns']}")
                st.markdown("---")
        else:
            st.info("No recent scans")
    
    def _render_key_metrics(self, scan_data: Dict):
        """Render key security metrics"""
        stats = scan_data.get('statistics', {})
        risk_dist = stats.get('risk_distribution', {})
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Total Vulnerabilities",
                stats.get('total_vulnerabilities', 0),
                help="Total number of security issues found"
            )
        
        with col2:
            st.metric(
                "High Risk",
                risk_dist.get('High', 0),
                delta=f"{risk_dist.get('High', 0) - risk_dist.get('Medium', 0)}",
                delta_color="inverse"
            )
        
        with col3:
            st.metric(
                "Coverage Score",
                f"{stats.get('unique_urls', 0)}/100",
                help="Number of unique URLs tested"
            )
        
        with col4:
            # Calculate security score
            total = stats.get('total_vulnerabilities', 1)
            high_risk = risk_dist.get('High', 0)
            score = max(0, 10 - (high_risk * 3) - (total * 0.5))
            
            st.metric(
                "Security Score",
                f"{score:.1f}/10",
                delta=f"{score - 5:.1f}",
                delta_color="normal" if score >= 7 else "inverse"
            )
    
    def _render_risk_summary_table(self, scan_data: Dict):
        """Render risk distribution summary table"""
        st.markdown("### 🎯 Risk Distribution Summary")
        
        stats = scan_data.get('statistics', {})
        risk_dist = stats.get('risk_distribution', {})
        
        if any(risk_dist.values()):
            # Create columns for risk levels
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                if risk_dist.get('High', 0) > 0:
                    st.error(f"🔴 **High Risk**  \n{risk_dist.get('High', 0)} issues")
                else:
                    st.success("🔴 **High Risk**  \n0 issues")
            
            with col2:
                if risk_dist.get('Medium', 0) > 0:
                    st.warning(f"🟡 **Medium Risk**  \n{risk_dist.get('Medium', 0)} issues")
                else:
                    st.success("🟡 **Medium Risk**  \n0 issues")
            
            with col3:
                if risk_dist.get('Low', 0) > 0:
                    st.info(f"🟢 **Low Risk**  \n{risk_dist.get('Low', 0)} issues")
                else:
                    st.success("🟢 **Low Risk**  \n0 issues")
            
            with col4:
                if risk_dist.get('Informational', 0) > 0:
                    st.info(f"🔵 **Info**  \n{risk_dist.get('Informational', 0)} issues")
                else:
                    st.success("🔵 **Info**  \n0 issues")
        else:
            st.success("🎉 No vulnerabilities found!")
    
    def _render_vulnerability_trends_chart(self, scan_data: Dict):
        """Render vulnerability categories summary"""
        st.markdown("### 📈 Vulnerability Categories")
        
        stats = scan_data.get('statistics', {})
        categories = stats.get('categories', {})
        
        if categories:
            # Display categories as metrics
            cols = st.columns(min(len(categories), 4))
            for i, (category, count) in enumerate(categories.items()):
                with cols[i % 4]:
                    st.metric(category.replace('_', ' ').title(), count)
        else:
            st.info("No category data available")
    
    def _render_vulnerability_details(self, scan_data: Dict):
        """Render detailed vulnerability table"""
        st.markdown("### 🔍 Vulnerability Details")
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        if vulnerabilities:
            # Create DataFrame
            df_data = []
            for vuln in vulnerabilities:
                df_data.append({
                    'Name': vuln.get('name', 'Unknown'),
                    'Risk': vuln.get('risk', 'Unknown'),
                    'Confidence': vuln.get('confidence', 'Unknown'),
                    'URL': vuln.get('url', 'Unknown')[:50] + '...' if len(vuln.get('url', '')) > 50 else vuln.get('url', 'Unknown'),
                    'CWE': vuln.get('cwe_id', 'N/A')
                })
            
            df = pd.DataFrame(df_data)
            
            # Color code by risk
            def color_risk(val):
                color_map = {
                    'High': 'background-color: #ffebee',
                    'Medium': 'background-color: #fff3e0',
                    'Low': 'background-color: #e8f5e8',
                    'Informational': 'background-color: #e3f2fd'
                }
                return color_map.get(val, '')
            
            styled_df = df.style.applymap(color_risk, subset=['Risk'])
            st.dataframe(styled_df, use_container_width=True)
            
            # Download button
            csv = df.to_csv(index=False)
            st.download_button(
                label="📥 Download as CSV",
                data=csv,
                file_name=f"vulnerabilities_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )
        else:
            st.info("No vulnerability details available")
    
    def _get_available_reports(self) -> List[Dict]:
        """Get list of available reports"""
        reports = []
        
        # Scan reports directory
        if config.REPORTS_DIR.exists():
            for report_file in config.REPORTS_DIR.glob("*.pdf"):
                reports.append({
                    'id': report_file.stem,
                    'name': report_file.stem,
                    'date': datetime.fromtimestamp(report_file.stat().st_mtime).strftime('%Y-%m-%d'),
                    'path': str(report_file),
                    'vuln_count': 0,  # Would be extracted from report
                    'high_risk': 0,   # Would be extracted from report
                    'score': 7.5      # Would be calculated
                })
        
        return reports
    
    def _download_report(self, report_path: str):
        """Download report file"""
        try:
            with open(report_path, 'rb') as f:
                bytes_data = f.read()
            
            st.download_button(
                label="💾 Download Report",
                data=bytes_data,
                file_name=Path(report_path).name,
                mime="application/pdf"
            )
        except Exception as e:
            st.error(f"Download failed: {e}")
    
    def _view_report(self, report_path: str):
        """View report inline"""
        st.info("Report viewing feature coming soon!")
    
    def _delete_report(self, report_path: str):
        """Delete report file"""
        try:
            Path(report_path).unlink()
            st.success("Report deleted successfully!")
            st.rerun()
        except Exception as e:
            st.error(f"Delete failed: {e}")

def main():
    """Main Streamlit app"""
    # Initialize session state
    if 'selected_tab' not in st.session_state:
        st.session_state.selected_tab = 'scanner'
    
    # Run the app
    app = StreamlitPentestUI()
    app.run()

if __name__ == "__main__":
    main() 