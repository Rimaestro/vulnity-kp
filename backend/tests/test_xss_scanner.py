"""
Test XSS Scanner functionality
Based on DVWA testing findings and existing test patterns
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import Response

from app.services.scanner.xss_scanner import XSSScanner
from app.models.vulnerability import VulnerabilityType, VulnerabilityRisk


class TestXSSScanner:
    """Test XSS Scanner implementation based on DVWA findings"""
    
    @pytest.fixture
    def xss_scanner(self):
        """Create XSS scanner instance"""
        return XSSScanner()
    
    @pytest.fixture
    def mock_response(self):
        """Create mock HTTP response"""
        response = MagicMock(spec=Response)
        response.status_code = 200
        response.headers = {'content-type': 'text/html'}
        response.url = "http://localhost/dvwa/vulnerabilities/xss_r/"
        return response
    
    def test_xss_scanner_initialization(self, xss_scanner):
        """Test XSS scanner initialization"""
        assert xss_scanner is not None
        assert len(xss_scanner.payloads) > 0
        assert len(xss_scanner.detection_patterns) > 0
        
        # Check payload categories based on DVWA testing
        payload_types = [p['type'] for p in xss_scanner.payloads]
        assert 'reflected' in payload_types
        assert 'stored' in payload_types
        assert 'dom' in payload_types
    
    def test_xss_payload_database(self, xss_scanner):
        """Test XSS payload database based on DVWA findings"""
        payloads = xss_scanner.payloads
        
        # Check for basic script payloads (tested successfully on DVWA)
        script_payloads = [p for p in payloads if '<script>' in p['payload']]
        assert len(script_payloads) > 0
        
        # Check for image onerror payloads (tested successfully on DVWA)
        img_payloads = [p for p in payloads if '<img' in p['payload'] and 'onerror' in p['payload']]
        assert len(img_payloads) > 0
        
        # Check for SVG payloads
        svg_payloads = [p for p in payloads if '<svg' in p['payload']]
        assert len(svg_payloads) > 0
        
        # Verify payload structure
        for payload in payloads:
            assert 'name' in payload
            assert 'payload' in payload
            assert 'type' in payload
            assert 'context' in payload
            assert 'risk' in payload
            assert 'description' in payload
            assert 'cwe_id' in payload
    
    def test_detection_patterns(self, xss_scanner):
        """Test XSS detection patterns"""
        patterns = xss_scanner.detection_patterns
        
        # Check pattern categories
        assert 'script_execution' in patterns
        assert 'event_handlers' in patterns
        assert 'html_injection' in patterns
        assert 'url_patterns' in patterns
        
        # Verify script execution patterns
        script_patterns = patterns['script_execution']
        assert any('script' in pattern for pattern in script_patterns)
        assert any('alert' in pattern for pattern in script_patterns)
    
    @pytest.mark.asyncio
    async def test_reflected_xss_detection(self, xss_scanner, mock_response):
        """Test reflected XSS detection based on DVWA findings"""
        
        # Mock baseline response
        baseline_response = MagicMock(spec=Response)
        baseline_response.status_code = 200
        baseline_response.text = "Hello test"
        baseline_response.headers = {'content-type': 'text/html'}
        
        # Mock malicious response with XSS payload reflected
        malicious_response = MagicMock(spec=Response)
        malicious_response.status_code = 200
        malicious_response.text = "Hello <script>alert('XSS')</script>"
        malicious_response.headers = {'content-type': 'text/html'}
        
        # Test payload info
        payload_info = {
            'name': 'Basic Script Alert',
            'payload': "<script>alert('XSS')</script>",
            'type': 'reflected',
            'context': 'html',
            'risk': VulnerabilityRisk.HIGH,
            'description': 'Basic script tag injection',
            'cwe_id': 'CWE-79'
        }
        
        # Test detection
        is_vulnerable, confidence, evidence = xss_scanner._detect_reflected_xss(
            baseline_response, malicious_response, payload_info
        )
        
        assert is_vulnerable is True
        assert confidence >= 0.7
        assert evidence['payload_reflected'] is True
        assert 'payload_reflection' in evidence['detection_methods']
    
    @pytest.mark.asyncio
    async def test_dom_xss_detection(self, xss_scanner, mock_response):
        """Test DOM XSS detection based on DVWA findings"""
        
        # Mock response with DOM XSS indicators
        mock_response.text = """
        <script>
            var default_value = location.search.substring(1);
            document.write("<script>alert('DOM-XSS')</script>");
        </script>
        """
        mock_response.url = "http://localhost/dvwa/vulnerabilities/xss_d/?default=<script>alert('DOM-XSS')</script>"
        
        payload_info = {
            'name': 'DOM Script Injection',
            'payload': "<script>alert('DOM-XSS')</script>",
            'type': 'dom',
            'context': 'html',
            'risk': VulnerabilityRisk.HIGH,
            'description': 'DOM-based script injection',
            'cwe_id': 'CWE-79'
        }
        
        # Test detection
        is_vulnerable, confidence, evidence = xss_scanner._detect_dom_xss(
            mock_response, payload_info
        )
        
        assert is_vulnerable is True
        assert confidence >= 0.7
        assert 'dom_manipulation_document.write' in evidence['detection_methods']
    
    @pytest.mark.asyncio
    async def test_stored_xss_detection(self, xss_scanner, mock_response):
        """Test stored XSS detection based on DVWA findings"""
        
        # Mock response with stored XSS content (like DVWA guestbook)
        mock_response.text = """
        <div>
            Name: TestUser<br>
            Message: <script>alert('Stored-XSS')</script>
        </div>
        """
        
        payload_info = {
            'name': 'Stored Script Alert',
            'payload': "<script>alert('Stored-XSS')</script>",
            'type': 'stored',
            'context': 'html',
            'risk': VulnerabilityRisk.CRITICAL,
            'description': 'Stored XSS with script tag',
            'cwe_id': 'CWE-79'
        }
        
        form_data = {
            'txtName': 'TestUser',
            'mtxMessage': "<script>alert('Stored-XSS')</script>"
        }
        
        # Test detection
        is_vulnerable, confidence, evidence = xss_scanner._detect_stored_xss(
            mock_response, payload_info, form_data
        )
        
        assert is_vulnerable is True
        assert confidence >= 0.8  # Higher threshold for stored XSS
        assert 'payload_stored_and_reflected' in evidence['detection_methods']
    
    @pytest.mark.asyncio
    async def test_parameter_extraction(self, xss_scanner):
        """Test parameter extraction from URLs"""
        
        # Test URL with parameters (like DVWA)
        url = "http://localhost/dvwa/vulnerabilities/xss_r/?name=test&id=1"
        parameters = xss_scanner._extract_parameters(url)
        
        assert 'name' in parameters
        assert 'id' in parameters
        assert parameters['name'] == 'test'
        assert parameters['id'] == '1'
        
        # Check common parameters are added
        assert 'search' in parameters
        assert 'query' in parameters
    
    @pytest.mark.asyncio
    async def test_vulnerability_type_mapping(self, xss_scanner):
        """Test XSS type to vulnerability type mapping"""
        
        # Test reflected XSS mapping
        reflected_type = xss_scanner._map_xss_type_to_vuln_type('reflected')
        assert reflected_type == VulnerabilityType.XSS_REFLECTED
        
        # Test stored XSS mapping
        stored_type = xss_scanner._map_xss_type_to_vuln_type('stored')
        assert stored_type == VulnerabilityType.XSS_STORED
        
        # Test DOM XSS mapping
        dom_type = xss_scanner._map_xss_type_to_vuln_type('dom')
        assert dom_type == VulnerabilityType.XSS_DOM
    
    @pytest.mark.asyncio
    async def test_scan_integration(self, xss_scanner):
        """Test full XSS scan integration"""
        
        with patch.object(xss_scanner, '_make_request') as mock_request:
            # Mock successful response
            mock_response = MagicMock(spec=Response)
            mock_response.status_code = 200
            mock_response.text = "Hello <script>alert('XSS')</script>"
            mock_response.headers = {'content-type': 'text/html'}
            mock_response.url = "http://localhost/dvwa/vulnerabilities/xss_r/"
            mock_request.return_value = mock_response
            
            # Mock form discovery
            with patch.object(xss_scanner, '_discover_forms') as mock_forms:
                mock_forms.return_value = []
                
                # Run scan
                target_url = "http://localhost/dvwa/vulnerabilities/xss_r/?name=test"
                results = await xss_scanner.scan(target_url)
                
                # Verify scan results structure
                assert 'target_url' in results
                assert 'scan_type' in results
                assert 'vulnerabilities' in results
                assert 'scan_summary' in results
                assert 'scan_metadata' in results
                
                assert results['scan_type'] == 'xss'
                assert results['target_url'] == target_url
                
                # Check summary structure
                summary = results['scan_summary']
                assert 'total_tests' in summary
                assert 'vulnerabilities_found' in summary
                assert 'reflected_xss' in summary
                assert 'stored_xss' in summary
                assert 'dom_xss' in summary
    
    @pytest.mark.asyncio
    async def test_error_handling(self, xss_scanner):
        """Test XSS scanner error handling"""
        
        with patch.object(xss_scanner, '_make_request') as mock_request:
            # Mock request failure
            mock_request.return_value = None
            
            # Run scan
            target_url = "http://invalid-url"
            results = await xss_scanner.scan(target_url)
            
            # Should handle errors gracefully
            assert 'error' in results or results['scan_summary']['vulnerabilities_found'] == 0
    
    def test_risk_count_updates(self, xss_scanner):
        """Test risk level count updates"""
        
        scan_results = {
            'scan_summary': {
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0
            }
        }
        
        # Test critical risk update
        xss_scanner._update_risk_counts(scan_results, VulnerabilityRisk.CRITICAL.value)
        assert scan_results['scan_summary']['critical_count'] == 1
        
        # Test high risk update
        xss_scanner._update_risk_counts(scan_results, VulnerabilityRisk.HIGH.value)
        assert scan_results['scan_summary']['high_count'] == 1
        
        # Test medium risk update
        xss_scanner._update_risk_counts(scan_results, VulnerabilityRisk.MEDIUM.value)
        assert scan_results['scan_summary']['medium_count'] == 1
