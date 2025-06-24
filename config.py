"""
Configuration settings for AI-Augmented Web Pentesting Assistant
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables (safely)
try:
    load_dotenv()
except UnicodeDecodeError:
    # Ignore .env file if it has encoding issues
    pass

class Config:
    """Configuration class for the pentesting assistant"""
    
    # Project paths
    PROJECT_ROOT = Path(__file__).parent
    SCANS_DIR = PROJECT_ROOT / "scans"
    REPORTS_DIR = PROJECT_ROOT / "reports"
    TEMPLATES_DIR = PROJECT_ROOT / "templates"
    SAMPLE_OUTPUTS_DIR = PROJECT_ROOT / "sample_outputs"
    
    # Create directories if they don't exist
    SCANS_DIR.mkdir(exist_ok=True)
    REPORTS_DIR.mkdir(exist_ok=True)
    TEMPLATES_DIR.mkdir(exist_ok=True)
    SAMPLE_OUTPUTS_DIR.mkdir(exist_ok=True)
    
    # API Configuration
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL = "gpt-4"
    OPENAI_MAX_TOKENS = 1500
    OPENAI_TEMPERATURE = 0.3
    
    # ZAP Configuration
    ZAP_API_KEY = ""  # Leave empty for no API key
    ZAP_PROXY_HOST = "127.0.0.1"
    ZAP_PROXY_PORT = 8080
    ZAP_TIMEOUT = 300  # 5 minutes
    
    # Scan Configuration
    DEFAULT_SCAN_POLICY = "Default Policy"
    MAX_SCAN_DEPTH = 5
    INCLUDE_SPIDER = True
    INCLUDE_ACTIVE_SCAN = True
    
    # Report Configuration
    REPORT_TITLE = "AI-Augmented Web Application Security Assessment"
    REPORT_AUTHOR = "AutoPent.AI Security Assistant"
    REPORT_VERSION = "1.0"
    
    # CVSS Configuration
    CVSS_VERSION = "3.1"
    
    # Risk thresholds
    RISK_THRESHOLDS = {
        "CRITICAL": 9.0,
        "HIGH": 7.0,
        "MEDIUM": 4.0,
        "LOW": 0.1,
        "INFO": 0.0
    }
    
    # Vulnerability categories
    VULN_CATEGORIES = {
        "injection": ["SQL Injection", "XSS", "Command Injection", "LDAP Injection"],
        "authentication": ["Broken Authentication", "Session Management"],
        "data_exposure": ["Sensitive Data Exposure", "Information Disclosure"],
        "access_control": ["Broken Access Control", "Privilege Escalation"],
        "security_config": ["Security Misconfiguration", "Default Credentials"],
        "known_vulns": ["Known Vulnerabilities", "Outdated Components"],
        "logging": ["Insufficient Logging", "Monitoring Failures"],
        "business_logic": ["Business Logic Flaws", "Race Conditions"]
    }
    
    # AI Prompts
    VULNERABILITY_ANALYSIS_PROMPT = """
    You are a cybersecurity expert analyzing a web application vulnerability.
    
    Vulnerability Details:
    - Name: {name}
    - Description: {description}
    - URL: {url}
    - Risk Level: {risk}
    - CWE ID: {cwe_id}
    
    Please provide a comprehensive analysis in the following format:
    
    1. **What is this vulnerability?**
       Explain in simple terms what this security issue is.
    
    2. **Why is it dangerous?**
       Describe the potential impact and what an attacker could do.
    
    3. **How to fix it?**
       Provide specific, actionable remediation steps.
    
    4. **Prevention measures:**
       Suggest best practices to prevent this in the future.
    
    Keep your response professional and technical but accessible.
    """
    
    CVSS_CALCULATION_PROMPT = """
    Based on this vulnerability information, help calculate CVSS 3.1 metrics:
    
    Vulnerability: {name}
    Description: {description}
    
    Consider these CVSS 3.1 metrics and suggest values:
    - Attack Vector (Network/Adjacent/Local/Physical)
    - Attack Complexity (Low/High)
    - Privileges Required (None/Low/High)
    - User Interaction (None/Required)
    - Scope (Unchanged/Changed)
    - Confidentiality Impact (None/Low/High)
    - Integrity Impact (None/Low/High)
    - Availability Impact (None/Low/High)
    
    Provide your reasoning and suggested CVSS score.
    """

# Global config instance
config = Config() 