"""
CVSS module for AI-Augmented Web Pentesting Assistant
"""

from .calculate import CVSSCalculator, VulnerabilityRiskAssessment, calculate_cvss_score

__all__ = ['CVSSCalculator', 'VulnerabilityRiskAssessment', 'calculate_cvss_score'] 