"""
Scanner module for AI-Augmented Web Pentesting Assistant
"""

from .run_zap_scan import scan_website, WebSecurityScanner

# Backward compatibility alias
scan_target = scan_website
ZAPScanner = WebSecurityScanner

__all__ = ['scan_website', 'scan_target', 'WebSecurityScanner', 'ZAPScanner'] 