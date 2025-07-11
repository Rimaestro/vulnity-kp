"""
Detection Signatures Module
Based on comprehensive DVWA payload testing results
Implements pattern matching for various SQL injection types
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    LFI = "lfi"
    RFI = "rfi"
    COMMAND_INJECTION = "command_injection"


class ConfidenceLevel(Enum):
    LOW = 0.3
    MEDIUM = 0.6
    HIGH = 0.8
    CRITICAL = 0.95


@dataclass
class DetectionResult:
    detected: bool
    confidence: float
    patterns_matched: List[str]
    extracted_data: List[str]
    vulnerability_type: VulnerabilityType
    details: Dict[str, Any]


class SQLInjectionSignatures:
    """
    SQL Injection detection signatures based on DVWA testing results
    70% success rate with specific patterns identified
    """
    
    def __init__(self):
        self.signatures = self._initialize_signatures()
        
    def _initialize_signatures(self) -> Dict[str, Any]:
        """
        Initialize detection signatures based on testing results
        """
        return {
            # Boolean-based SQL Injection (Payload 1, 5, 9, 10)
            "boolean_based": {
                "success_indicators": [
                    "Gordon Brown",      # User from DVWA testing
                    "Pablo Picasso",     # User from DVWA testing  
                    "Hack Me",          # User from DVWA testing
                    "Bob Smith",        # User from DVWA testing
                    "admin",            # Admin user
                    "First name:",      # DVWA output format
                    "Surname:",         # DVWA output format
                ],
                "patterns": [
                    r"ID:\s*[^<\n]+\s*First name:\s*[^<\n]+\s*Surname:\s*[^<\n]+",
                    r"(Gordon Brown|Pablo Picasso|Hack Me|Bob Smith|admin)",
                    r"First name:\s*(admin|Gordon|Pablo|Hack|Bob)",
                ],
                "confidence_threshold": 2,  # Minimum indicators for positive detection
                "severity": "high"
            },
            
            # Union-based SQL Injection (Payload 6, 7)
            "union_based": {
                "success_indicators": [
                    "root@localhost",        # Database user (Payload 7)
                    "10.4.32-MariaDB",      # Database version (Payload 7)
                    "mysql",                # Database type
                    "localhost",            # Host information
                    "MariaDB",              # Database system
                ],
                "critical_indicators": [
                    "root@localhost",        # Critical: Database credentials
                    r"\d+\.\d+\.\d+-MariaDB", # Critical: Version disclosure
                ],
                "patterns": [
                    r"root@localhost",
                    r"\d+\.\d+\.\d+-MariaDB",
                    r"First name:\s*(root@localhost|\d+)",
                    r"Surname:\s*(\d+\.\d+\.\d+-MariaDB|\d+)",
                ],
                "confidence_threshold": 1,
                "severity": "critical"
            },
            
            # Time-based SQL Injection (Payload 8)
            "time_based": {
                "time_thresholds": {
                    "sleep_3": {"min": 2.5, "max": 3.5},
                    "sleep_5": {"min": 4.5, "max": 5.5},
                    "sleep_10": {"min": 9.0, "max": 11.0}
                },
                "confidence_calculation": "linear",  # Based on delay accuracy
                "severity": "medium"
            },
            
            # Error-based Information Disclosure (Payload 2, 3, 4)
            "error_based": {
                "error_patterns": [
                    r"Fatal error:",
                    r"mysqli_sql_exception:",
                    r"You have an error in your SQL syntax",
                    r"MariaDB server version",
                    r"Warning:",
                    r"Notice:",
                ],
                "information_patterns": [
                    r"C:\\xampp\\htdocs\\[^\\]+\\[^\\]+\.php",  # Windows paths
                    r"/var/www/[^/]+/[^/]+\.php",              # Linux paths
                    r"line \d+",                               # Line numbers
                    r"mysqli_[a-z_]+",                         # MySQL functions
                    r"in\s+[A-Z]:\\[^\\]+\\[^\\]+\.php",      # File paths in errors
                ],
                "critical_disclosures": [
                    r"C:\\xampp\\htdocs\\dvwa\\vulnerabilities\\sqli\\source\\low\.php",
                    r"line 11",  # Specific line from DVWA testing
                    r"mysqli_query",  # Function from DVWA testing
                ],
                "confidence_threshold": 1,
                "severity": "medium"
            },
            
            # Blind Boolean SQL Injection (Payload 9, 10)
            "blind_boolean": {
                "true_condition_indicators": [
                    "admin",
                    "First name:",
                    "Surname:",
                ],
                "false_condition_indicators": [
                    "",  # Empty response
                    "No results",
                    "User ID not found",
                ],
                "comparison_required": True,  # Requires true/false comparison
                "confidence_threshold": 0.8,
                "severity": "medium"
            }
        }
    
    def detect_boolean_based(self, response_text: str) -> DetectionResult:
        """
        Detect boolean-based SQL injection based on DVWA testing
        """
        signatures = self.signatures["boolean_based"]
        indicators = signatures["success_indicators"]
        patterns = signatures["patterns"]

        found_indicators = []
        matched_patterns = []

        # Check for success indicators (more specific matching)
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                found_indicators.append(indicator)

        # Check for regex patterns
        for pattern in patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                matched_patterns.extend(matches)

        # More strict detection - require multiple unique user names, not just indicators
        unique_users = set()
        user_names = ["Gordon", "Pablo", "Hack", "Bob", "admin"]
        for user in user_names:
            if user.lower() in response_text.lower():
                unique_users.add(user)

        # Calculate confidence based on unique users found
        indicator_count = len(unique_users)
        confidence = min(indicator_count * 0.3, 1.0)

        # Determine if vulnerable - require at least 2 different users
        vulnerable = indicator_count >= signatures["confidence_threshold"]

        return DetectionResult(
            detected=vulnerable,
            confidence=confidence,
            patterns_matched=matched_patterns,
            extracted_data=list(unique_users) + [ind for ind in found_indicators if ind not in user_names],
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            details={
                "injection_type": "boolean_based",
                "users_extracted": list(unique_users),
                "bypass_successful": vulnerable,
                "indicator_count": indicator_count
            }
        )
    
    def detect_union_based(self, response_text: str) -> DetectionResult:
        """
        Detect union-based SQL injection with system information extraction
        """
        signatures = self.signatures["union_based"]
        indicators = signatures["success_indicators"]
        critical_indicators = signatures["critical_indicators"]
        patterns = signatures["patterns"]
        
        found_indicators = []
        found_critical = []
        matched_patterns = []
        
        # Check for success indicators
        for indicator in indicators:
            if indicator in response_text:
                found_indicators.append(indicator)
        
        # Check for critical indicators
        for indicator in critical_indicators:
            if isinstance(indicator, str):
                if indicator in response_text:
                    found_critical.append(indicator)
            else:  # regex pattern
                matches = re.findall(indicator, response_text)
                found_critical.extend(matches)
        
        # Check for regex patterns
        for pattern in patterns:
            matches = re.findall(pattern, response_text)
            if matches:
                matched_patterns.extend(matches)
        
        # Calculate confidence
        base_confidence = 0.7 if found_indicators else 0.0
        critical_bonus = 0.2 if found_critical else 0.0
        confidence = min(base_confidence + critical_bonus, 1.0)
        
        # Determine if vulnerable
        vulnerable = len(found_indicators) >= signatures["confidence_threshold"]
        
        return DetectionResult(
            detected=vulnerable,
            confidence=confidence,
            patterns_matched=matched_patterns,
            extracted_data=found_indicators + found_critical,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            details={
                "injection_type": "union_based",
                "system_info_extracted": found_critical,
                "data_extraction": True,
                "critical_disclosure": bool(found_critical)
            }
        )
    
    def detect_time_based(self, response_time: float, expected_delay: float = 5.0) -> DetectionResult:
        """
        Detect time-based SQL injection based on response delay
        """
        signatures = self.signatures["time_based"]
        thresholds = signatures["time_thresholds"]

        # Determine which threshold matches
        matched_threshold = None
        for threshold_name, threshold_data in thresholds.items():
            if threshold_data["min"] <= response_time <= threshold_data["max"]:
                matched_threshold = threshold_name
                break

        # Calculate confidence based on delay accuracy
        if matched_threshold:
            expected = expected_delay
            actual = response_time
            accuracy = 1.0 - abs(expected - actual) / expected
            confidence = max(accuracy, 0.5)  # Minimum 50% confidence
        else:
            confidence = 0.0

        # More strict detection - only detect if within expected thresholds
        vulnerable = matched_threshold is not None

        return DetectionResult(
            detected=vulnerable,
            confidence=confidence,
            patterns_matched=[matched_threshold] if matched_threshold else [],
            extracted_data=[f"Response delay: {response_time:.2f}s"],
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            details={
                "injection_type": "time_based",
                "response_time": response_time,
                "expected_delay": expected_delay,
                "threshold_matched": matched_threshold,
                "delay_accuracy": confidence
            }
        )
    
    def detect_error_based(self, response_text: str) -> DetectionResult:
        """
        Detect error-based information disclosure
        """
        signatures = self.signatures["error_based"]
        error_patterns = signatures["error_patterns"]
        info_patterns = signatures["information_patterns"]
        critical_patterns = signatures["critical_disclosures"]
        
        found_errors = []
        found_info = []
        found_critical = []
        
        # Check for error patterns
        for pattern in error_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            found_errors.extend(matches)
        
        # Check for information patterns
        for pattern in info_patterns:
            matches = re.findall(pattern, response_text)
            found_info.extend(matches)
        
        # Check for critical disclosures
        for pattern in critical_patterns:
            matches = re.findall(pattern, response_text)
            found_critical.extend(matches)
        
        # Calculate confidence
        error_weight = 0.3
        info_weight = 0.4
        critical_weight = 0.6
        
        confidence = min(
            len(found_errors) * error_weight +
            len(found_info) * info_weight +
            len(found_critical) * critical_weight,
            1.0
        )
        
        vulnerable = len(found_errors) > 0 or len(found_info) > 0
        
        return DetectionResult(
            detected=vulnerable,
            confidence=confidence,
            patterns_matched=found_errors + found_info + found_critical,
            extracted_data=found_info + found_critical,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            details={
                "injection_type": "error_based",
                "errors_found": found_errors,
                "information_disclosed": found_info,
                "critical_disclosures": found_critical,
                "information_disclosure": True
            }
        )
