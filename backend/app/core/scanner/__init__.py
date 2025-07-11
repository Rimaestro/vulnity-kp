"""
Vulnity Scanner Core Modules
Based on comprehensive DVWA analysis and testing
"""

from .authentication import AuthenticationManager
from .sql_injection import SQLInjectionScanner, SQLInjectionType, Severity, SQLInjectionResult
from .detection_signatures import SQLInjectionSignatures, VulnerabilityType, DetectionResult
from .vulnity_scanner import VulnityScanner, quick_scan

__all__ = [
    'AuthenticationManager',
    'SQLInjectionScanner',
    'SQLInjectionType',
    'Severity',
    'SQLInjectionResult',
    'SQLInjectionSignatures',
    'VulnerabilityType',
    'DetectionResult',
    'VulnityScanner',
    'quick_scan'
]

__version__ = "1.0.0"
__author__ = "Vulnity Team"
__description__ = "Web Vulnerability Scanner based on DVWA analysis"
