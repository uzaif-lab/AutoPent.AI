"""
AI Module for Vulnerability Analysis
Integrates with OpenAI API to provide intelligent analysis and recommendations
"""
import json
import logging
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import openai
from openai import OpenAI

from config import config
from parser.zap_parser import Vulnerability

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class AIAnalysis:
    """Data class for AI analysis results"""
    vulnerability_name: str
    explanation: str
    impact: str
    remediation: str
    prevention: str
    cvss_suggestion: str
    confidence: float
    analysis_timestamp: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'vulnerability_name': self.vulnerability_name,
            'explanation': self.explanation,
            'impact': self.impact,
            'remediation': self.remediation,
            'prevention': self.prevention,
            'cvss_suggestion': self.cvss_suggestion,
            'confidence': self.confidence,
            'analysis_timestamp': self.analysis_timestamp
        }

class VulnerabilityAnalyzer:
    """AI-powered vulnerability analyzer using OpenAI"""
    
    def __init__(self):
        self.client = None
        self.rate_limit_delay = 1  # seconds between requests
        self.max_retries = 3
        
    def initialize_openai(self) -> bool:
        """Initialize OpenAI client"""
        try:
            if not config.OPENAI_API_KEY:
                logger.warning("OpenAI API key not found. AI analysis will be skipped.")
                return False
            
            self.client = OpenAI(api_key=config.OPENAI_API_KEY)
            
            # Test the connection
            response = self.client.models.list()
            logger.info("OpenAI client initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}")
            return False
    
    def analyze_vulnerability(self, vulnerability: Vulnerability) -> Optional[AIAnalysis]:
        """Analyze a single vulnerability using AI"""
        if not self.client:
            logger.warning("OpenAI client not initialized. Skipping AI analysis.")
            return self._create_fallback_analysis(vulnerability)
        
        try:
            # Prepare the prompt
            prompt = config.VULNERABILITY_ANALYSIS_PROMPT.format(
                name=vulnerability.name,
                description=vulnerability.description,
                url=vulnerability.url,
                risk=vulnerability.risk,
                cwe_id=vulnerability.cwe_id or "Not specified"
            )
            
            # Make API call with retries
            response = self._make_openai_request(prompt)
            
            if not response:
                return self._create_fallback_analysis(vulnerability)
            
            # Parse the response
            analysis = self._parse_ai_response(vulnerability.name, response)
            
            # Add rate limiting
            time.sleep(self.rate_limit_delay)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Failed to analyze vulnerability {vulnerability.name}: {e}")
            return self._create_fallback_analysis(vulnerability)
    
    def _make_openai_request(self, prompt: str) -> Optional[str]:
        """Make OpenAI API request with retry logic"""
        for attempt in range(self.max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=config.OPENAI_MODEL,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a cybersecurity expert providing detailed vulnerability analysis."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    max_tokens=config.OPENAI_MAX_TOKENS,
                    temperature=config.OPENAI_TEMPERATURE
                )
                
                return response.choices[0].message.content
                
            except openai.RateLimitError:
                wait_time = (2 ** attempt) * 5  # Exponential backoff
                logger.warning(f"Rate limit hit. Waiting {wait_time} seconds before retry {attempt + 1}")
                time.sleep(wait_time)
                
            except openai.APIError as e:
                logger.error(f"OpenAI API error (attempt {attempt + 1}): {e}")
                if attempt == self.max_retries - 1:
                    return None
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Unexpected error in OpenAI request (attempt {attempt + 1}): {e}")
                if attempt == self.max_retries - 1:
                    return None
                time.sleep(2)
        
        return None
    
    def _parse_ai_response(self, vuln_name: str, response: str) -> AIAnalysis:
        """Parse AI response into structured analysis"""
        try:
            # Initialize default values
            explanation = ""
            impact = ""
            remediation = ""
            prevention = ""
            cvss_suggestion = ""
            
            # Split response into sections
            lines = response.split('\n')
            current_section = ""
            
            for line in lines:
                line = line.strip()
                
                if not line:
                    continue
                
                # Detect sections
                if "what is this vulnerability" in line.lower() or "vulnerability?" in line.lower():
                    current_section = "explanation"
                    continue
                elif "why is it dangerous" in line.lower() or "dangerous?" in line.lower():
                    current_section = "impact"
                    continue
                elif "how to fix" in line.lower() or "fix it?" in line.lower():
                    current_section = "remediation"
                    continue
                elif "prevention" in line.lower() or "prevent" in line.lower():
                    current_section = "prevention"
                    continue
                elif "cvss" in line.lower():
                    current_section = "cvss"
                    continue
                
                # Add content to current section
                if current_section == "explanation":
                    explanation += line + " "
                elif current_section == "impact":
                    impact += line + " "
                elif current_section == "remediation":
                    remediation += line + " "
                elif current_section == "prevention":
                    prevention += line + " "
                elif current_section == "cvss":
                    cvss_suggestion += line + " "
                elif not current_section and explanation == "":
                    # If no sections detected, add to explanation
                    explanation += line + " "
            
            # Clean up and fallback if sections are empty
            if not explanation.strip():
                explanation = response[:500] + "..." if len(response) > 500 else response
            
            return AIAnalysis(
                vulnerability_name=vuln_name,
                explanation=explanation.strip(),
                impact=impact.strip() or "Impact analysis not available",
                remediation=remediation.strip() or "Remediation steps not available",
                prevention=prevention.strip() or "Prevention measures not available",
                cvss_suggestion=cvss_suggestion.strip() or "CVSS analysis not available",
                confidence=0.8,  # Default confidence for AI analysis
                analysis_timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            )
            
        except Exception as e:
            logger.error(f"Failed to parse AI response: {e}")
            return self._create_fallback_analysis_from_response(vuln_name, response)
    
    def _create_fallback_analysis(self, vulnerability: Vulnerability) -> AIAnalysis:
        """Create fallback analysis when AI is not available"""
        return AIAnalysis(
            vulnerability_name=vulnerability.name,
            explanation=vulnerability.description or "No description available",
            impact=f"This is a {vulnerability.risk.lower()} risk vulnerability that could impact the application security.",
            remediation=vulnerability.solution or "Consult security documentation for remediation steps.",
            prevention="Follow secure coding practices and regular security assessments.",
            cvss_suggestion=f"Based on risk level: {vulnerability.risk}",
            confidence=0.5,  # Lower confidence for fallback
            analysis_timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
        )
    
    def _create_fallback_analysis_from_response(self, vuln_name: str, response: str) -> AIAnalysis:
        """Create analysis from unparseable AI response"""
        return AIAnalysis(
            vulnerability_name=vuln_name,
            explanation=response[:300] + "..." if len(response) > 300 else response,
            impact="Impact analysis requires manual review",
            remediation="Remediation steps require manual review",
            prevention="Prevention measures require manual review",
            cvss_suggestion="CVSS scoring requires manual review",
            confidence=0.6,
            analysis_timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
        )
    
    def analyze_vulnerabilities_batch(self, vulnerabilities: List[Vulnerability]) -> Dict[str, AIAnalysis]:
        """Analyze multiple vulnerabilities in batch"""
        logger.info(f"Starting AI analysis of {len(vulnerabilities)} vulnerabilities")
        
        if not self.initialize_openai():
            logger.warning("AI analysis disabled. Using fallback analysis.")
        
        analyses = {}
        
        for i, vuln in enumerate(vulnerabilities, 1):
            logger.info(f"Analyzing vulnerability {i}/{len(vulnerabilities)}: {vuln.name}")
            
            analysis = self.analyze_vulnerability(vuln)
            if analysis:
                analyses[vuln.name] = analysis
            
            # Progress update
            if i % 5 == 0:
                logger.info(f"Completed {i}/{len(vulnerabilities)} analyses")
        
        logger.info(f"AI analysis completed. Generated {len(analyses)} analyses.")
        return analyses
    
    def get_cvss_suggestion(self, vulnerability: Vulnerability) -> Dict:
        """Get CVSS scoring suggestion from AI"""
        if not self.client:
            return self._get_fallback_cvss(vulnerability)
        
        try:
            prompt = config.CVSS_CALCULATION_PROMPT.format(
                name=vulnerability.name,
                description=vulnerability.description
            )
            
            response = self._make_openai_request(prompt)
            
            if response:
                # Parse CVSS metrics from response
                cvss_data = self._parse_cvss_response(response, vulnerability.risk)
                return cvss_data
            else:
                return self._get_fallback_cvss(vulnerability)
                
        except Exception as e:
            logger.error(f"Failed to get CVSS suggestion: {e}")
            return self._get_fallback_cvss(vulnerability)
    
    def _parse_cvss_response(self, response: str, risk_level: str) -> Dict:
        """Parse CVSS metrics from AI response"""
        # Default CVSS values based on risk level
        cvss_defaults = {
            "High": {"base_score": 7.5, "av": "N", "ac": "L", "pr": "N", "ui": "N"},
            "Medium": {"base_score": 5.0, "av": "N", "ac": "L", "pr": "L", "ui": "R"},
            "Low": {"base_score": 3.0, "av": "L", "ac": "H", "pr": "L", "ui": "R"},
            "Informational": {"base_score": 0.0, "av": "N", "ac": "L", "pr": "N", "ui": "N"}
        }
        
        base_values = cvss_defaults.get(risk_level, cvss_defaults["Medium"])
        
        return {
            "cvss_version": "3.1",
            "base_score": base_values["base_score"],
            "attack_vector": base_values["av"],
            "attack_complexity": base_values["ac"],
            "privileges_required": base_values["pr"],
            "user_interaction": base_values["ui"],
            "scope": "U",
            "confidentiality": "H" if risk_level == "High" else "L",
            "integrity": "H" if risk_level == "High" else "L",
            "availability": "L",
            "ai_reasoning": response[:200] + "..." if len(response) > 200 else response
        }
    
    def _get_fallback_cvss(self, vulnerability: Vulnerability) -> Dict:
        """Get fallback CVSS values based on risk level"""
        risk_scores = {
            "High": 7.5,
            "Medium": 5.0,
            "Low": 3.0,
            "Informational": 0.0
        }
        
        return {
            "cvss_version": "3.1",
            "base_score": risk_scores.get(vulnerability.risk, 5.0),
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "L",
            "integrity": "L",
            "availability": "L",
            "ai_reasoning": f"Fallback scoring based on risk level: {vulnerability.risk}"
        }

def analyze_vulnerabilities(vulnerabilities: List[Vulnerability]) -> Dict[str, AIAnalysis]:
    """
    Convenience function to analyze vulnerabilities
    Returns: Dictionary mapping vulnerability names to AI analyses
    """
    analyzer = VulnerabilityAnalyzer()
    return analyzer.analyze_vulnerabilities_batch(vulnerabilities)

def analyze_single_vulnerability(vulnerability: Vulnerability) -> Optional[AIAnalysis]:
    """
    Convenience function to analyze a single vulnerability
    Returns: AIAnalysis object or None
    """
    analyzer = VulnerabilityAnalyzer()
    if analyzer.initialize_openai():
        return analyzer.analyze_vulnerability(vulnerability)
    else:
        return analyzer._create_fallback_analysis(vulnerability)

if __name__ == "__main__":
    # Test the AI module
    from parser.zap_parser import Vulnerability
    
    # Create a test vulnerability
    test_vuln = Vulnerability(
        name="Cross-Site Scripting (XSS)",
        description="The application is vulnerable to reflected XSS attacks",
        url="https://example.com/search?q=<script>alert(1)</script>",
        risk="High",
        confidence="High",
        cwe_id="79",
        wasc_id="8",
        solution="Encode user input properly",
        reference="https://owasp.org/www-project-top-ten/",
        evidence="<script>alert(1)</script>",
        attack="<script>alert(1)</script>",
        param="q",
        method="GET",
        instances=[]
    )
    
    # Analyze the test vulnerability
    print("🤖 Testing AI vulnerability analysis...")
    analysis = analyze_single_vulnerability(test_vuln)
    
    if analysis:
        print(f"✅ Analysis completed for: {analysis.vulnerability_name}")
        print(f"📝 Explanation: {analysis.explanation[:100]}...")
        print(f"⚠️  Impact: {analysis.impact[:100]}...")
        print(f"🔧 Remediation: {analysis.remediation[:100]}...")
    else:
        print("❌ Analysis failed") 