"""
CVSS Calculator Module
Calculates CVSS v3.1 scores for vulnerabilities
"""
import math
import logging
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from config import config

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AttackVector(Enum):
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"

class AttackComplexity(Enum):
    LOW = "L"
    HIGH = "H"

class PrivilegesRequired(Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"

class UserInteraction(Enum):
    NONE = "N"
    REQUIRED = "R"

class Scope(Enum):
    UNCHANGED = "U"
    CHANGED = "C"

class Impact(Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"

@dataclass
class CVSSMetrics:
    """CVSS v3.1 metrics data class"""
    attack_vector: AttackVector
    attack_complexity: AttackComplexity
    privileges_required: PrivilegesRequired
    user_interaction: UserInteraction
    scope: Scope
    confidentiality: Impact
    integrity: Impact
    availability: Impact
    
    def to_dict(self) -> Dict:
        """Convert metrics to dictionary"""
        return {
            'attack_vector': self.attack_vector.value,
            'attack_complexity': self.attack_complexity.value,
            'privileges_required': self.privileges_required.value,
            'user_interaction': self.user_interaction.value,
            'scope': self.scope.value,
            'confidentiality': self.confidentiality.value,
            'integrity': self.integrity.value,
            'availability': self.availability.value
        }

@dataclass
class CVSSScore:
    """CVSS score result"""
    base_score: float
    impact_score: float
    exploitability_score: float
    severity: str
    vector_string: str
    metrics: CVSSMetrics
    
    def to_dict(self) -> Dict:
        """Convert score to dictionary"""
        return {
            'base_score': self.base_score,
            'impact_score': self.impact_score,
            'exploitability_score': self.exploitability_score,
            'severity': self.severity,
            'vector_string': self.vector_string,
            'metrics': self.metrics.to_dict()
        }

class CVSSCalculator:
    """CVSS v3.1 Base Score Calculator"""
    
    # CVSS v3.1 metric values
    ATTACK_VECTOR_VALUES = {
        AttackVector.NETWORK: 0.85,
        AttackVector.ADJACENT: 0.62,
        AttackVector.LOCAL: 0.55,
        AttackVector.PHYSICAL: 0.2
    }
    
    ATTACK_COMPLEXITY_VALUES = {
        AttackComplexity.LOW: 0.77,
        AttackComplexity.HIGH: 0.44
    }
    
    PRIVILEGES_REQUIRED_VALUES = {
        # Scope Unchanged
        (PrivilegesRequired.NONE, Scope.UNCHANGED): 0.85,
        (PrivilegesRequired.LOW, Scope.UNCHANGED): 0.62,
        (PrivilegesRequired.HIGH, Scope.UNCHANGED): 0.27,
        # Scope Changed
        (PrivilegesRequired.NONE, Scope.CHANGED): 0.85,
        (PrivilegesRequired.LOW, Scope.CHANGED): 0.68,
        (PrivilegesRequired.HIGH, Scope.CHANGED): 0.50
    }
    
    USER_INTERACTION_VALUES = {
        UserInteraction.NONE: 0.85,
        UserInteraction.REQUIRED: 0.62
    }
    
    IMPACT_VALUES = {
        Impact.NONE: 0.0,
        Impact.LOW: 0.22,
        Impact.HIGH: 0.56
    }
    
    @classmethod
    def calculate_score(cls, metrics: CVSSMetrics) -> CVSSScore:
        """Calculate CVSS v3.1 base score"""
        try:
            # Calculate Impact Sub Score (ISS)
            iss = cls._calculate_impact_subscore(metrics)
            
            # Calculate Impact Score
            if metrics.scope == Scope.UNCHANGED:
                impact_score = 6.42 * iss
            else:  # Scope.CHANGED
                impact_score = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
            
            # Calculate Exploitability Score
            exploitability_score = cls._calculate_exploitability_score(metrics)
            
            # Calculate Base Score
            if impact_score <= 0:
                base_score = 0.0
            elif metrics.scope == Scope.UNCHANGED:
                base_score = min(10.0, impact_score + exploitability_score)
            else:  # Scope.CHANGED
                base_score = min(10.0, 1.08 * (impact_score + exploitability_score))
            
            # Round up to nearest 0.1
            base_score = math.ceil(base_score * 10) / 10
            
            # Determine severity
            severity = cls._get_severity_rating(base_score)
            
            # Generate vector string
            vector_string = cls._generate_vector_string(metrics)
            
            return CVSSScore(
                base_score=base_score,
                impact_score=round(impact_score, 1),
                exploitability_score=round(exploitability_score, 1),
                severity=severity,
                vector_string=vector_string,
                metrics=metrics
            )
            
        except Exception as e:
            logger.error(f"Failed to calculate CVSS score: {e}")
            return cls._create_default_score(metrics)
    
    @classmethod
    def _calculate_impact_subscore(cls, metrics: CVSSMetrics) -> float:
        """Calculate Impact Sub Score (ISS)"""
        c_impact = cls.IMPACT_VALUES[metrics.confidentiality]
        i_impact = cls.IMPACT_VALUES[metrics.integrity]
        a_impact = cls.IMPACT_VALUES[metrics.availability]
        
        return 1 - ((1 - c_impact) * (1 - i_impact) * (1 - a_impact))
    
    @classmethod
    def _calculate_exploitability_score(cls, metrics: CVSSMetrics) -> float:
        """Calculate Exploitability Score"""
        av = cls.ATTACK_VECTOR_VALUES[metrics.attack_vector]
        ac = cls.ATTACK_COMPLEXITY_VALUES[metrics.attack_complexity]
        pr = cls.PRIVILEGES_REQUIRED_VALUES[(metrics.privileges_required, metrics.scope)]
        ui = cls.USER_INTERACTION_VALUES[metrics.user_interaction]
        
        return 8.22 * av * ac * pr * ui
    
    @classmethod
    def _get_severity_rating(cls, score: float) -> str:
        """Get severity rating based on score"""
        if score == 0.0:
            return "None"
        elif 0.1 <= score <= 3.9:
            return "Low"
        elif 4.0 <= score <= 6.9:
            return "Medium"
        elif 7.0 <= score <= 8.9:
            return "High"
        elif 9.0 <= score <= 10.0:
            return "Critical"
        else:
            return "Unknown"
    
    @classmethod
    def _generate_vector_string(cls, metrics: CVSSMetrics) -> str:
        """Generate CVSS vector string"""
        return (f"CVSS:3.1/"
                f"AV:{metrics.attack_vector.value}/"
                f"AC:{metrics.attack_complexity.value}/"
                f"PR:{metrics.privileges_required.value}/"
                f"UI:{metrics.user_interaction.value}/"
                f"S:{metrics.scope.value}/"
                f"C:{metrics.confidentiality.value}/"
                f"I:{metrics.integrity.value}/"
                f"A:{metrics.availability.value}")
    
    @classmethod
    def _create_default_score(cls, metrics: CVSSMetrics) -> CVSSScore:
        """Create default score when calculation fails"""
        return CVSSScore(
            base_score=5.0,
            impact_score=3.6,
            exploitability_score=2.8,
            severity="Medium",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            metrics=metrics
        )

class VulnerabilityRiskAssessment:
    """Risk assessment for vulnerabilities"""
    
    def __init__(self):
        self.calculator = CVSSCalculator()
    
    def assess_vulnerability_risk(self, vuln_name: str, vuln_data: Dict) -> Dict:
        """Assess risk for a vulnerability"""
        try:
            # Extract or infer CVSS metrics
            metrics = self._infer_cvss_metrics(vuln_name, vuln_data)
            
            # Calculate CVSS score
            cvss_score = self.calculator.calculate_score(metrics)
            
            # Additional risk factors
            risk_factors = self._analyze_risk_factors(vuln_data)
            
            # Business impact assessment
            business_impact = self._assess_business_impact(cvss_score.severity)
            
            return {
                'vulnerability_name': vuln_name,
                'cvss_score': cvss_score.to_dict(),
                'risk_factors': risk_factors,
                'business_impact': business_impact,
                'remediation_priority': self._get_remediation_priority(cvss_score.base_score, risk_factors)
            }
            
        except Exception as e:
            logger.error(f"Failed to assess risk for {vuln_name}: {e}")
            return self._create_default_assessment(vuln_name, vuln_data)
    
    def _infer_cvss_metrics(self, vuln_name: str, vuln_data: Dict) -> CVSSMetrics:
        """Infer CVSS metrics based on vulnerability data"""
        # Default values
        av = AttackVector.NETWORK
        ac = AttackComplexity.LOW
        pr = PrivilegesRequired.NONE
        ui = UserInteraction.NONE
        s = Scope.UNCHANGED
        c = Impact.LOW
        i = Impact.LOW
        a = Impact.LOW
        
        vuln_name_lower = vuln_name.lower()
        risk_level = vuln_data.get('risk', 'Medium').lower()
        
        # Infer based on vulnerability type
        if any(keyword in vuln_name_lower for keyword in ['xss', 'cross-site scripting']):
            c = Impact.LOW
            i = Impact.LOW
            a = Impact.NONE
            s = Scope.CHANGED
            
        elif any(keyword in vuln_name_lower for keyword in ['sql injection', 'sqli']):
            c = Impact.HIGH
            i = Impact.HIGH
            a = Impact.LOW
            
        elif any(keyword in vuln_name_lower for keyword in ['csrf', 'cross-site request']):
            pr = PrivilegesRequired.NONE
            ui = UserInteraction.REQUIRED
            c = Impact.LOW
            i = Impact.LOW
            
        elif any(keyword in vuln_name_lower for keyword in ['path traversal', 'directory traversal']):
            c = Impact.HIGH
            i = Impact.NONE
            a = Impact.NONE
            
        elif any(keyword in vuln_name_lower for keyword in ['rce', 'command injection', 'code execution']):
            c = Impact.HIGH
            i = Impact.HIGH
            a = Impact.HIGH
            
        elif any(keyword in vuln_name_lower for keyword in ['authentication', 'auth']):
            c = Impact.HIGH
            i = Impact.LOW
            a = Impact.NONE
            
        elif any(keyword in vuln_name_lower for keyword in ['information disclosure', 'information leakage']):
            c = Impact.LOW
            i = Impact.NONE
            a = Impact.NONE
        
        # Adjust based on risk level
        if risk_level == 'high':
            if c == Impact.LOW:
                c = Impact.HIGH
            if i == Impact.LOW:
                i = Impact.HIGH
        elif risk_level == 'low':
            if c == Impact.HIGH:
                c = Impact.LOW
            if i == Impact.HIGH:
                i = Impact.LOW
        
        return CVSSMetrics(av, ac, pr, ui, s, c, i, a)
    
    def _analyze_risk_factors(self, vuln_data: Dict) -> Dict:
        """Analyze additional risk factors"""
        factors = {
            'exploitability': 'Medium',
            'public_exploit_available': False,
            'authentication_required': True,
            'network_accessible': True,
            'data_sensitivity': 'Medium'
        }
        
        # Analyze based on vulnerability data
        confidence = vuln_data.get('confidence', 'Medium').lower()
        if confidence == 'high':
            factors['exploitability'] = 'High'
        elif confidence == 'low':
            factors['exploitability'] = 'Low'
        
        # Check if vulnerability affects authentication
        vuln_name = vuln_data.get('name', '').lower()
        if 'auth' in vuln_name or 'login' in vuln_name:
            factors['authentication_required'] = False
            factors['data_sensitivity'] = 'High'
        
        return factors
    
    def _assess_business_impact(self, severity: str) -> Dict:
        """Assess business impact based on severity"""
        impact_levels = {
            'Critical': {
                'financial_impact': 'Very High',
                'reputation_impact': 'High',
                'operational_impact': 'High',
                'compliance_impact': 'High'
            },
            'High': {
                'financial_impact': 'High',
                'reputation_impact': 'Medium',
                'operational_impact': 'Medium',
                'compliance_impact': 'Medium'
            },
            'Medium': {
                'financial_impact': 'Medium',
                'reputation_impact': 'Low',
                'operational_impact': 'Low',
                'compliance_impact': 'Low'
            },
            'Low': {
                'financial_impact': 'Low',
                'reputation_impact': 'Very Low',
                'operational_impact': 'Very Low',
                'compliance_impact': 'Very Low'
            }
        }
        
        return impact_levels.get(severity, impact_levels['Medium'])
    
    def _get_remediation_priority(self, cvss_score: float, risk_factors: Dict) -> str:
        """Determine remediation priority"""
        if cvss_score >= 9.0:
            return "Critical - Immediate action required"
        elif cvss_score >= 7.0:
            return "High - Remediate within 24-48 hours"
        elif cvss_score >= 4.0:
            return "Medium - Remediate within 1-2 weeks"
        elif cvss_score >= 0.1:
            return "Low - Remediate in next maintenance cycle"
        else:
            return "Informational - Monitor and review"
    
    def _create_default_assessment(self, vuln_name: str, vuln_data: Dict) -> Dict:
        """Create default assessment when calculation fails"""
        return {
            'vulnerability_name': vuln_name,
            'cvss_score': {
                'base_score': 5.0,
                'severity': 'Medium',
                'vector_string': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
            },
            'risk_factors': {
                'exploitability': 'Medium',
                'public_exploit_available': False,
                'authentication_required': True,
                'network_accessible': True
            },
            'business_impact': {
                'financial_impact': 'Medium',
                'reputation_impact': 'Low',
                'operational_impact': 'Low'
            },
            'remediation_priority': 'Medium - Remediate within 1-2 weeks'
        }

def calculate_cvss_score(attack_vector: str, attack_complexity: str, 
                        privileges_required: str, user_interaction: str,
                        scope: str, confidentiality: str, 
                        integrity: str, availability: str) -> CVSSScore:
    """
    Convenience function to calculate CVSS score from string values
    """
    try:
        metrics = CVSSMetrics(
            attack_vector=AttackVector(attack_vector.upper()),
            attack_complexity=AttackComplexity(attack_complexity.upper()),
            privileges_required=PrivilegesRequired(privileges_required.upper()),
            user_interaction=UserInteraction(user_interaction.upper()),
            scope=Scope(scope.upper()),
            confidentiality=Impact(confidentiality.upper()),
            integrity=Impact(integrity.upper()),
            availability=Impact(availability.upper())
        )
        
        return CVSSCalculator.calculate_score(metrics)
        
    except Exception as e:
        logger.error(f"Failed to calculate CVSS score: {e}")
        # Return default score
        default_metrics = CVSSMetrics(
            AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE,
            UserInteraction.NONE, Scope.UNCHANGED, Impact.LOW, Impact.LOW, Impact.LOW
        )
        return CVSSCalculator.calculate_score(default_metrics)

if __name__ == "__main__":
    # Test CVSS calculation
    print("🔢 Testing CVSS Calculator...")
    
    # Test case: XSS vulnerability
    test_score = calculate_cvss_score(
        attack_vector="N",
        attack_complexity="L", 
        privileges_required="N",
        user_interaction="R",
        scope="C",
        confidentiality="L",
        integrity="L", 
        availability="N"
    )
    
    print(f"✅ CVSS Score: {test_score.base_score}")
    print(f"📊 Severity: {test_score.severity}")
    print(f"🔗 Vector: {test_score.vector_string}")
    
    # Test risk assessment
    risk_assessor = VulnerabilityRiskAssessment()
    test_vuln = {
        'name': 'Cross-Site Scripting (XSS)',
        'risk': 'High',
        'confidence': 'High'
    }
    
    assessment = risk_assessor.assess_vulnerability_risk('XSS Test', test_vuln)
    print(f"🎯 Assessment: {assessment['remediation_priority']}") 