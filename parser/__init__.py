"""
Parser module for vulnerability scan reports
"""

from .zap_parser import parse_zap_report, ZapReportParser, Vulnerability

__all__ = ['parse_zap_report', 'ZapReportParser', 'Vulnerability'] 