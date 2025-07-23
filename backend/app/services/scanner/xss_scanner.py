"""
XSS Scanner Service for Cross-Site Scripting vulnerability detection
Based on DVWA testing findings and existing BaseScanner patterns
"""

import asyncio
import time
import re
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from app.config.logging import get_logger
from app.config.settings import settings
from app.models.vulnerability import VulnerabilityType, VulnerabilityRisk
from .base import BaseScanner


class XSSScanner(BaseScanner):
    """
    Concrete XSS Scanner implementation
    Based on DVWA testing findings and existing codebase patterns
    """
    
    def __init__(self):
        super().__init__()
        self.logger = get_logger("scanner.xss")
        self.payloads = self._load_xss_payloads()
        self.detection_patterns = self._load_detection_patterns()
        
    def _load_xss_payloads(self) -> List[Dict[str, Any]]:
        """
        Load XSS payloads based on DVWA testing findings
        Organized by context and effectiveness
        """
        return [
            # Basic script tag payloads (tested successfully on DVWA)
            {
                'name': 'Basic Script Alert',
                'payload': "<script>alert('XSS')</script>",
                'type': 'reflected',
                'context': 'html',
                'risk': VulnerabilityRisk.HIGH,
                'description': 'Basic script tag injection with alert function',
                'cwe_id': 'CWE-79'
            },
            {
                'name': 'Script Alert with Single Quotes',
                'payload': "<script>alert(1)</script>",
                'type': 'reflected',
                'context': 'html',
                'risk': VulnerabilityRisk.HIGH,
                'description': 'Script injection with numeric alert',
                'cwe_id': 'CWE-79'
            },
            
            # Image onerror payloads (tested successfully on DVWA)
            {
                'name': 'Image onerror Alert',
                'payload': "<img src=x onerror=alert('XSS')>",
                'type': 'reflected',
                'context': 'html',
                'risk': VulnerabilityRisk.HIGH,
                'description': 'Image tag with onerror event handler',
                'cwe_id': 'CWE-79'
            },
            {
                'name': 'Image onerror Numeric',
                'payload': "<img src=x onerror=alert(1)>",
                'type': 'reflected',
                'context': 'html',
                'risk': VulnerabilityRisk.HIGH,
                'description': 'Image onerror with numeric alert',
                'cwe_id': 'CWE-79'
            },
            
            # SVG-based payloads
            {
                'name': 'SVG onload Alert',
                'payload': "<svg onload=alert('XSS')>",
                'type': 'reflected',
                'context': 'html',
                'risk': VulnerabilityRisk.HIGH,
                'description': 'SVG element with onload event',
                'cwe_id': 'CWE-79'
            },
            {
                'name': 'SVG onload Numeric',
                'payload': "<svg/onload=alert(1)>",
                'type': 'reflected',
                'context': 'html',
                'risk': VulnerabilityRisk.HIGH,
                'description': 'Compact SVG onload injection',
                'cwe_id': 'CWE-79'
            },
            
            # Attribute context payloads
            {
                'name': 'Attribute onmouseover',
                'payload': "' onmouseover=alert('XSS') '",
                'type': 'reflected',
                'context': 'attribute',
                'risk': VulnerabilityRisk.HIGH,
                'description': 'Attribute escape with event handler',
                'cwe_id': 'CWE-79'
            },
            {
                'name': 'Attribute onload',
                'payload': '" onload=alert(1) "',
                'type': 'reflected',
                'context': 'attribute',
                'risk': VulnerabilityRisk.HIGH,
                'description': 'Double quote escape with onload',
                'cwe_id': 'CWE-79'
            },
            
            # JavaScript context payloads
            {
                'name': 'JavaScript String Escape',
                'payload': "';alert('XSS');//",
                'type': 'reflected',
                'context': 'javascript',
                'risk': VulnerabilityRisk.HIGH,
                'description': 'JavaScript string context escape',
                'cwe_id': 'CWE-79'
            },
            {
                'name': 'JavaScript Double Quote Escape',
                'payload': '";alert(1);//',
                'type': 'reflected',
                'context': 'javascript',
                'risk': VulnerabilityRisk.HIGH,
                'description': 'JavaScript double quote escape',
                'cwe_id': 'CWE-79'
            },
            
            # URL/href context payloads
            {
                'name': 'JavaScript Protocol',
                'payload': "javascript:alert('XSS')",
                'type': 'reflected',
                'context': 'url',
                'risk': VulnerabilityRisk.MEDIUM,
                'description': 'JavaScript protocol injection',
                'cwe_id': 'CWE-79'
            },
            
            # DOM-based payloads (based on DVWA DOM XSS findings)
            {
                'name': 'DOM Script Injection',
                'payload': "<script>alert('DOM-XSS')</script>",
                'type': 'dom',
                'context': 'html',
                'risk': VulnerabilityRisk.HIGH,
                'description': 'DOM-based script injection',
                'cwe_id': 'CWE-79'
            },
            
            # Stored XSS payloads (based on DVWA stored XSS findings)
            {
                'name': 'Stored Script Alert',
                'payload': "<script>alert('Stored-XSS')</script>",
                'type': 'stored',
                'context': 'html',
                'risk': VulnerabilityRisk.CRITICAL,
                'description': 'Stored XSS with script tag',
                'cwe_id': 'CWE-79'
            },
            {
                'name': 'Stored Image onerror',
                'payload': "<img src=x onerror=alert('Stored')>",
                'type': 'stored',
                'context': 'html',
                'risk': VulnerabilityRisk.CRITICAL,
                'description': 'Stored XSS with image onerror',
                'cwe_id': 'CWE-79'
            }
        ]
    
    def _load_detection_patterns(self) -> Dict[str, List[str]]:
        """
        Load detection patterns based on DVWA testing findings
        """
        return {
            'script_execution': [
                r'<script[^>]*>.*?</script>',
                r'<script[^>]*>',
                r'javascript:',
                r'alert\s*\(',
                r'confirm\s*\(',
                r'prompt\s*\('
            ],
            'event_handlers': [
                r'on\w+\s*=\s*["\'][^"\']*["\']',
                r'onerror\s*=',
                r'onload\s*=',
                r'onmouseover\s*=',
                r'onclick\s*=',
                r'onfocus\s*='
            ],
            'html_injection': [
                r'<img[^>]*>',
                r'<svg[^>]*>',
                r'<iframe[^>]*>',
                r'<object[^>]*>',
                r'<embed[^>]*>'
            ],
            'url_patterns': [
                r'javascript:',
                r'data:text/html',
                r'vbscript:'
            ]
        }
    
    async def scan(self, target_url: str, **kwargs) -> Dict[str, Any]:
        """
        Perform comprehensive XSS scan
        Following existing BaseScanner patterns
        """
        
        self.logger.info(f"Starting XSS scan for: {target_url}")
        
        scan_results = {
            'target_url': target_url,
            'scan_type': 'xss',
            'vulnerabilities': [],
            'scan_summary': {
                'total_tests': 0,
                'vulnerabilities_found': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'reflected_xss': 0,
                'stored_xss': 0,
                'dom_xss': 0
            },
            'scan_metadata': {
                'start_time': time.time(),
                'end_time': None,
                'duration': None,
                'parameters_tested': [],
                'forms_tested': [],
                'contexts_tested': []
            }
        }
        
        try:
            # Extract parameters and forms for testing
            parameters = self._extract_parameters(target_url)
            forms = await self._discover_forms(target_url)
            
            # Test reflected XSS via URL parameters
            await self._test_reflected_xss_parameters(target_url, parameters, scan_results)
            
            # Test reflected XSS via forms
            await self._test_reflected_xss_forms(target_url, forms, scan_results)
            
            # Test DOM-based XSS
            await self._test_dom_xss(target_url, scan_results)
            
            # Test stored XSS (if forms are available)
            if forms:
                await self._test_stored_xss(target_url, forms, scan_results)
            
            # Finalize scan metadata
            scan_results['scan_metadata']['end_time'] = time.time()
            scan_results['scan_metadata']['duration'] = (
                scan_results['scan_metadata']['end_time'] - 
                scan_results['scan_metadata']['start_time']
            )
            
            self.logger.info(
                f"XSS scan completed. Found {scan_results['scan_summary']['vulnerabilities_found']} "
                f"vulnerabilities in {scan_results['scan_metadata']['duration']:.2f} seconds"
            )
            
            return scan_results
            
        except Exception as e:
            self.logger.error(f"Error during XSS scan: {str(e)}")
            scan_results['error'] = str(e)
            return scan_results
    
    def _extract_parameters(self, url: str) -> Dict[str, str]:
        """
        Extract parameters from URL for testing
        Enhanced based on DVWA parameter discovery
        """
        parameters = {}
        
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            for param_name, param_values in query_params.items():
                if param_values:
                    parameters[param_name] = param_values[0]
                else:
                    parameters[param_name] = ""
                    
            # Add common parameter names for discovery
            common_params = ['name', 'search', 'q', 'query', 'input', 'data', 'message', 'comment']
            for param in common_params:
                if param not in parameters:
                    parameters[param] = "test"
                    
        except Exception as e:
            self.logger.error(f"Error extracting parameters: {str(e)}")
            
        return parameters

    async def _discover_forms(self, url: str) -> List[Dict[str, Any]]:
        """
        Discover forms on the target page for XSS testing
        Based on DVWA form discovery patterns
        """
        forms = []

        try:
            response = await self._make_request(url, 'GET')
            if not response or response.status_code != 200:
                return forms

            content = response.text.lower()

            # Simple form detection (can be enhanced with proper HTML parsing)
            if '<form' in content:
                # Look for common form patterns found in DVWA
                form_patterns = [
                    {'action': 'xss_r', 'method': 'get', 'fields': ['name']},  # Reflected XSS form
                    {'action': 'xss_s', 'method': 'post', 'fields': ['txtname', 'mtxmessage']},  # Stored XSS form
                    {'action': '', 'method': 'post', 'fields': ['message', 'comment', 'input']},  # Generic forms
                ]

                for pattern in form_patterns:
                    if any(field in content for field in pattern['fields']):
                        forms.append({
                            'action': pattern['action'],
                            'method': pattern['method'],
                            'fields': pattern['fields'],
                            'url': url
                        })

        except Exception as e:
            self.logger.error(f"Error discovering forms: {str(e)}")

        return forms

    async def _test_reflected_xss_parameters(self, target_url: str, parameters: Dict[str, str], scan_results: Dict[str, Any]):
        """
        Test reflected XSS via URL parameters
        Based on DVWA reflected XSS testing findings
        """
        for param_name, param_value in parameters.items():
            scan_results['scan_metadata']['parameters_tested'].append(param_name)

            for payload_info in self.payloads:
                if payload_info['type'] in ['reflected', 'dom']:
                    scan_results['scan_summary']['total_tests'] += 1

                    vulnerability = await self._test_xss_payload(
                        target_url, param_name, param_value, payload_info, 'GET'
                    )

                    if vulnerability:
                        scan_results['vulnerabilities'].append(vulnerability)
                        scan_results['scan_summary']['vulnerabilities_found'] += 1
                        scan_results['scan_summary']['reflected_xss'] += 1

                        # Count by risk level
                        self._update_risk_counts(scan_results, vulnerability['risk'])

                        self.logger.warning(f"Reflected XSS vulnerability found: {vulnerability['title']}")

                    # Rate limiting
                    await asyncio.sleep(self.request_delay)

    async def _test_reflected_xss_forms(self, target_url: str, forms: List[Dict[str, Any]], scan_results: Dict[str, Any]):
        """
        Test reflected XSS via form submissions
        Based on DVWA form testing patterns
        """
        for form in forms:
            scan_results['scan_metadata']['forms_tested'].append(form)

            for field in form['fields']:
                for payload_info in self.payloads:
                    if payload_info['type'] == 'reflected':
                        scan_results['scan_summary']['total_tests'] += 1

                        vulnerability = await self._test_form_xss_payload(
                            target_url, form, field, payload_info
                        )

                        if vulnerability:
                            scan_results['vulnerabilities'].append(vulnerability)
                            scan_results['scan_summary']['vulnerabilities_found'] += 1
                            scan_results['scan_summary']['reflected_xss'] += 1

                            self._update_risk_counts(scan_results, vulnerability['risk'])

                            self.logger.warning(f"Form-based reflected XSS found: {vulnerability['title']}")

                        await asyncio.sleep(self.request_delay)

    async def _test_dom_xss(self, target_url: str, scan_results: Dict[str, Any]):
        """
        Test DOM-based XSS vulnerabilities
        Based on DVWA DOM XSS testing findings
        """
        dom_payloads = [p for p in self.payloads if p['type'] == 'dom']

        for payload_info in dom_payloads:
            scan_results['scan_summary']['total_tests'] += 1

            # Test via URL fragment (hash)
            test_url = f"{target_url}#{payload_info['payload']}"
            vulnerability = await self._test_dom_payload(test_url, payload_info, 'fragment')

            if vulnerability:
                scan_results['vulnerabilities'].append(vulnerability)
                scan_results['scan_summary']['vulnerabilities_found'] += 1
                scan_results['scan_summary']['dom_xss'] += 1

                self._update_risk_counts(scan_results, vulnerability['risk'])

                self.logger.warning(f"DOM XSS vulnerability found: {vulnerability['title']}")

            # Test via URL parameter (as found in DVWA)
            parsed_url = urlparse(target_url)
            query_params = parse_qs(parsed_url.query)
            query_params['default'] = [payload_info['payload']]

            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse((
                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                parsed_url.params, new_query, parsed_url.fragment
            ))

            vulnerability = await self._test_dom_payload(test_url, payload_info, 'parameter')

            if vulnerability:
                scan_results['vulnerabilities'].append(vulnerability)
                scan_results['scan_summary']['vulnerabilities_found'] += 1
                scan_results['scan_summary']['dom_xss'] += 1

                self._update_risk_counts(scan_results, vulnerability['risk'])

            await asyncio.sleep(self.request_delay)

    async def _test_stored_xss(self, target_url: str, forms: List[Dict[str, Any]], scan_results: Dict[str, Any]):
        """
        Test stored XSS vulnerabilities
        Based on DVWA stored XSS testing findings
        """
        stored_payloads = [p for p in self.payloads if p['type'] == 'stored']

        for form in forms:
            if form['method'].lower() == 'post':  # Stored XSS typically via POST
                for payload_info in stored_payloads:
                    scan_results['scan_summary']['total_tests'] += 1

                    vulnerability = await self._test_stored_payload(
                        target_url, form, payload_info
                    )

                    if vulnerability:
                        scan_results['vulnerabilities'].append(vulnerability)
                        scan_results['scan_summary']['vulnerabilities_found'] += 1
                        scan_results['scan_summary']['stored_xss'] += 1

                        self._update_risk_counts(scan_results, vulnerability['risk'])

                        self.logger.warning(f"Stored XSS vulnerability found: {vulnerability['title']}")

                    await asyncio.sleep(self.request_delay * 2)  # Longer delay for stored XSS

    async def _test_xss_payload(self, target_url: str, param_name: str, original_value: str,
                               payload_info: Dict[str, Any], method: str = 'GET') -> Optional[Dict[str, Any]]:
        """
        Test individual XSS payload via URL parameter
        Based on DVWA reflected XSS testing patterns
        """
        try:
            # Get baseline response first
            baseline_response = await self._make_baseline_request(target_url, param_name, original_value, method)
            if not baseline_response:
                return None

            # Test with XSS payload
            malicious_response = await self._make_malicious_request(
                target_url, param_name, payload_info['payload'], method
            )
            if not malicious_response:
                return None

            # Analyze responses for XSS vulnerability
            vulnerability = await self._analyze_xss_responses(
                baseline_response, malicious_response, payload_info, target_url, param_name, method
            )

            return vulnerability

        except Exception as e:
            self.logger.error(f"Error testing XSS payload: {str(e)}")
            return None

    async def _test_form_xss_payload(self, target_url: str, form: Dict[str, Any],
                                    field_name: str, payload_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Test XSS payload via form submission
        Based on DVWA form testing patterns
        """
        try:
            # Prepare form data
            form_data = {}
            for field in form['fields']:
                if field == field_name:
                    form_data[field] = payload_info['payload']
                else:
                    form_data[field] = "test"  # Default value for other fields

            # Get baseline response
            baseline_data = {field: "test" for field in form['fields']}
            baseline_response = await self._make_request(
                target_url, form['method'].upper(), data=baseline_data
            )

            if not baseline_response:
                return None

            # Test with malicious payload
            malicious_response = await self._make_request(
                target_url, form['method'].upper(), data=form_data
            )

            if not malicious_response:
                return None

            # Analyze responses
            vulnerability = await self._analyze_xss_responses(
                baseline_response, malicious_response, payload_info, target_url, field_name, form['method']
            )

            return vulnerability

        except Exception as e:
            self.logger.error(f"Error testing form XSS payload: {str(e)}")
            return None

    async def _test_dom_payload(self, test_url: str, payload_info: Dict[str, Any],
                               injection_method: str) -> Optional[Dict[str, Any]]:
        """
        Test DOM-based XSS payload
        Based on DVWA DOM XSS testing findings
        """
        try:
            response = await self._make_request(test_url, 'GET')
            if not response:
                return None

            # Check for DOM XSS indicators
            is_vulnerable, confidence, evidence = self._detect_dom_xss(response, payload_info)

            if is_vulnerable and confidence >= 0.7:
                return {
                    'title': f"DOM-based XSS - {payload_info['name']}",
                    'description': f"DOM-based XSS vulnerability via {injection_method}",
                    'vulnerability_type': VulnerabilityType.XSS_DOM.value,
                    'risk': payload_info['risk'].value,
                    'endpoint': test_url,
                    'parameter': injection_method,
                    'method': 'GET',
                    'payload': payload_info['payload'],
                    'confidence': confidence,
                    'evidence': evidence,
                    'cwe_id': payload_info['cwe_id'],
                    'owasp_category': 'A03:2021 – Injection',
                    'request_data': {
                        'url': test_url,
                        'method': 'GET',
                        'injection_method': injection_method
                    },
                    'response_data': {
                        'status_code': response.status_code,
                        'content_length': len(response.text),
                        'content_type': response.headers.get('content-type', '')
                    }
                }

            return None

        except Exception as e:
            self.logger.error(f"Error testing DOM XSS payload: {str(e)}")
            return None

    async def _test_stored_payload(self, target_url: str, form: Dict[str, Any],
                                  payload_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Test stored XSS payload
        Based on DVWA stored XSS testing findings
        """
        try:
            # Prepare form data with payload
            form_data = {}
            for field in form['fields']:
                if 'message' in field.lower() or 'comment' in field.lower():
                    form_data[field] = payload_info['payload']
                else:
                    form_data[field] = f"TestUser_{int(time.time())}"  # Unique identifier

            # Submit the payload
            submit_response = await self._make_request(
                target_url, form['method'].upper(), data=form_data
            )

            if not submit_response:
                return None

            # Wait a moment for storage
            await asyncio.sleep(1)

            # Check if payload is stored and executed
            check_response = await self._make_request(target_url, 'GET')
            if not check_response:
                return None

            # Analyze for stored XSS
            is_vulnerable, confidence, evidence = self._detect_stored_xss(
                check_response, payload_info, form_data
            )

            if is_vulnerable and confidence >= 0.8:
                return {
                    'title': f"Stored XSS - {payload_info['name']}",
                    'description': f"Stored XSS vulnerability in form field",
                    'vulnerability_type': VulnerabilityType.XSS_STORED.value,
                    'risk': VulnerabilityRisk.CRITICAL.value,  # Stored XSS is always critical
                    'endpoint': target_url,
                    'parameter': 'form_field',
                    'method': form['method'].upper(),
                    'payload': payload_info['payload'],
                    'confidence': confidence,
                    'evidence': evidence,
                    'cwe_id': payload_info['cwe_id'],
                    'owasp_category': 'A03:2021 – Injection',
                    'request_data': {
                        'url': target_url,
                        'method': form['method'].upper(),
                        'form_data': form_data
                    },
                    'response_data': {
                        'status_code': check_response.status_code,
                        'content_length': len(check_response.text),
                        'content_type': check_response.headers.get('content-type', '')
                    }
                }

            return None

        except Exception as e:
            self.logger.error(f"Error testing stored XSS payload: {str(e)}")
            return None

    async def _make_baseline_request(self, url: str, param_name: str, param_value: str, method: str = 'GET'):
        """Make baseline request for comparison"""
        try:
            if method.upper() == 'GET':
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                query_params[param_name] = [param_value]

                new_query = urlencode(query_params, doseq=True)
                test_url = urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                    parsed_url.params, new_query, parsed_url.fragment
                ))

                return await self._make_request(test_url, 'GET')
            else:
                data = {param_name: param_value}
                return await self._make_request(url, 'POST', data=data)

        except Exception as e:
            self.logger.error(f"Error making baseline request: {str(e)}")
            return None

    async def _make_malicious_request(self, url: str, param_name: str, payload: str, method: str = 'GET'):
        """Make malicious request with XSS payload"""
        try:
            if method.upper() == 'GET':
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                query_params[param_name] = [payload]

                new_query = urlencode(query_params, doseq=True)
                test_url = urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                    parsed_url.params, new_query, parsed_url.fragment
                ))

                return await self._make_request(test_url, 'GET')
            else:
                data = {param_name: payload}
                return await self._make_request(url, 'POST', data=data)

        except Exception as e:
            self.logger.error(f"Error making malicious request: {str(e)}")
            return None

    async def _analyze_xss_responses(self, baseline_response, malicious_response, payload_info: Dict[str, Any],
                                   target_url: str, param_name: str, method: str) -> Optional[Dict[str, Any]]:
        """
        Analyze responses for XSS vulnerability
        Based on DVWA testing findings and response patterns
        """
        try:
            payload_type = payload_info['type']
            is_vulnerable = False
            confidence = 0.0
            evidence = {}

            # Reflected XSS detection
            if payload_type == 'reflected':
                is_vulnerable, confidence, evidence = self._detect_reflected_xss(
                    baseline_response, malicious_response, payload_info
                )

            # DOM XSS detection
            elif payload_type == 'dom':
                is_vulnerable, confidence, evidence = self._detect_dom_xss(
                    malicious_response, payload_info
                )

            # If vulnerability detected, create vulnerability record
            confidence_threshold = getattr(settings, 'XSS_CONFIDENCE_THRESHOLD', 0.7)
            if is_vulnerable and confidence >= confidence_threshold:
                vuln_type = self._map_xss_type_to_vuln_type(payload_type)

                return {
                    'title': f"XSS ({payload_type.title()}) - {payload_info['name']}",
                    'description': payload_info['description'],
                    'vulnerability_type': vuln_type.value,
                    'risk': payload_info['risk'].value,
                    'endpoint': target_url,
                    'parameter': param_name,
                    'method': method.upper(),
                    'payload': payload_info['payload'],
                    'confidence': confidence,
                    'evidence': evidence,
                    'cwe_id': payload_info['cwe_id'],
                    'owasp_category': 'A03:2021 – Injection',
                    'request_data': {
                        'url': target_url,
                        'parameter': param_name,
                        'payload': payload_info['payload'],
                        'method': method
                    },
                    'response_data': {
                        'status_code': malicious_response.status_code,
                        'content_length': len(malicious_response.text),
                        'content_type': malicious_response.headers.get('content-type', ''),
                        'payload_reflected': payload_info['payload'] in malicious_response.text
                    }
                }

            return None

        except Exception as e:
            self.logger.error(f"Error analyzing XSS responses: {str(e)}")
            return None

    def _detect_reflected_xss(self, baseline_response, malicious_response, payload_info: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Detect reflected XSS based on DVWA testing patterns
        """
        try:
            malicious_content = malicious_response.text
            payload = payload_info['payload']
            evidence = {'detection_methods': [], 'payload_reflected': False, 'script_patterns': []}

            confidence = 0.0
            is_vulnerable = False

            # Check if payload is reflected in response
            if payload in malicious_content:
                evidence['payload_reflected'] = True
                evidence['detection_methods'].append('payload_reflection')
                confidence += 0.4

            # Check for script execution patterns
            for pattern_type, patterns in self.detection_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, malicious_content, re.IGNORECASE):
                        evidence['script_patterns'].append(f"{pattern_type}: {pattern}")
                        evidence['detection_methods'].append(f'pattern_match_{pattern_type}')
                        confidence += 0.3

            # Check for context-specific indicators
            context = payload_info.get('context', 'html')
            if context == 'html' and any(tag in malicious_content.lower() for tag in ['<script', '<img', '<svg']):
                evidence['detection_methods'].append('html_injection')
                confidence += 0.4

            # Check for JavaScript execution indicators (based on DVWA findings)
            js_indicators = ['alert(', 'confirm(', 'prompt(', 'javascript:']
            for indicator in js_indicators:
                if indicator in malicious_content.lower():
                    evidence['detection_methods'].append(f'js_execution_{indicator}')
                    confidence += 0.5

            # Check for response differences that indicate successful injection
            if (malicious_response.status_code != baseline_response.status_code or
                len(malicious_response.text) != len(baseline_response.text)):
                evidence['detection_methods'].append('response_difference')
                confidence += 0.2

            # Determine if vulnerable
            is_vulnerable = confidence >= 0.7

            return is_vulnerable, min(confidence, 1.0), evidence

        except Exception as e:
            self.logger.error(f"Error detecting reflected XSS: {str(e)}")
            return False, 0.0, {'error': str(e)}

    def _detect_dom_xss(self, response, payload_info: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Detect DOM-based XSS based on DVWA DOM XSS testing findings
        """
        try:
            content = response.text
            payload = payload_info['payload']
            evidence = {'detection_methods': [], 'dom_indicators': [], 'script_patterns': []}

            confidence = 0.0
            is_vulnerable = False

            # Check for DOM manipulation indicators
            dom_indicators = [
                'document.write',
                'innerHTML',
                'outerHTML',
                'document.location',
                'window.location',
                'location.hash',
                'location.search'
            ]

            for indicator in dom_indicators:
                if indicator in content:
                    evidence['dom_indicators'].append(indicator)
                    evidence['detection_methods'].append(f'dom_manipulation_{indicator}')
                    confidence += 0.3

            # Check if payload appears in JavaScript context
            if payload in content:
                evidence['detection_methods'].append('payload_in_dom')
                confidence += 0.4

            # Check for script execution patterns specific to DOM XSS
            script_patterns = [
                r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>',
                r'javascript:.*?' + re.escape(payload),
                r'eval\s*\([^)]*' + re.escape(payload)
            ]

            for pattern in script_patterns:
                if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                    evidence['script_patterns'].append(pattern)
                    evidence['detection_methods'].append('script_execution_pattern')
                    confidence += 0.5

            # Check for URL fragment processing (common in DOM XSS)
            if '#' in response.url and payload in response.url:
                evidence['detection_methods'].append('url_fragment_processing')
                confidence += 0.4

            is_vulnerable = confidence >= 0.7

            return is_vulnerable, min(confidence, 1.0), evidence

        except Exception as e:
            self.logger.error(f"Error detecting DOM XSS: {str(e)}")
            return False, 0.0, {'error': str(e)}

    def _detect_stored_xss(self, response, payload_info: Dict[str, Any], form_data: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Detect stored XSS based on DVWA stored XSS testing findings
        """
        try:
            content = response.text
            payload = payload_info['payload']
            evidence = {'detection_methods': [], 'storage_indicators': [], 'execution_indicators': []}

            confidence = 0.0
            is_vulnerable = False

            # Check if payload is stored and reflected in the page
            if payload in content:
                evidence['detection_methods'].append('payload_stored_and_reflected')
                confidence += 0.6

            # Check for form data persistence
            for field_name, field_value in form_data.items():
                if field_value != payload and field_value in content:
                    evidence['storage_indicators'].append(f'field_{field_name}_stored')
                    confidence += 0.2

            # Check for script execution in stored context
            script_indicators = [
                '<script',
                'onerror=',
                'onload=',
                'javascript:'
            ]

            for indicator in script_indicators:
                if indicator in content.lower():
                    evidence['execution_indicators'].append(indicator)
                    evidence['detection_methods'].append(f'script_indicator_{indicator}')
                    confidence += 0.3

            # Check for guestbook or comment-like structures (DVWA pattern)
            storage_patterns = [
                r'name:\s*[^<]*' + re.escape(payload),
                r'message:\s*[^<]*' + re.escape(payload),
                r'comment:\s*[^<]*' + re.escape(payload)
            ]

            for pattern in storage_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    evidence['detection_methods'].append('stored_in_structure')
                    confidence += 0.4

            is_vulnerable = confidence >= 0.8  # Higher threshold for stored XSS

            return is_vulnerable, min(confidence, 1.0), evidence

        except Exception as e:
            self.logger.error(f"Error detecting stored XSS: {str(e)}")
            return False, 0.0, {'error': str(e)}

    def _map_xss_type_to_vuln_type(self, xss_type: str) -> VulnerabilityType:
        """Map XSS type to VulnerabilityType enum"""
        type_mapping = {
            'reflected': VulnerabilityType.XSS_REFLECTED,
            'stored': VulnerabilityType.XSS_STORED,
            'dom': VulnerabilityType.XSS_DOM
        }
        return type_mapping.get(xss_type, VulnerabilityType.XSS_REFLECTED)

    def _update_risk_counts(self, scan_results: Dict[str, Any], risk: str):
        """Update risk level counts in scan results"""
        if risk == VulnerabilityRisk.CRITICAL.value:
            scan_results['scan_summary']['critical_count'] += 1
        elif risk == VulnerabilityRisk.HIGH.value:
            scan_results['scan_summary']['high_count'] += 1
        elif risk == VulnerabilityRisk.MEDIUM.value:
            scan_results['scan_summary']['medium_count'] += 1
