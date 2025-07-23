"""
Unit tests for SQL Injection Scanner
Testing concrete implementation based on DVWA analysis findings
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from typing import Dict, Any

from app.services.scanner.sql_injection import SQLInjectionScanner
from app.models.vulnerability import VulnerabilityType, VulnerabilityRisk


class TestSQLInjectionScanner:
    """Test cases for SQL Injection Scanner"""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance for testing"""
        return SQLInjectionScanner()
    
    @pytest.fixture
    def mock_response(self):
        """Create mock HTTP response"""
        response = Mock()
        response.text = "Normal response content"
        response.status_code = 200
        response.headers = {"Content-Type": "text/html"}
        return response
    
    @pytest.fixture
    def mock_error_response(self):
        """Create mock HTTP response with SQL error"""
        response = Mock()
        response.text = "You have an error in your SQL syntax; check the manual"
        response.status_code = 500
        response.headers = {"Content-Type": "text/html"}
        return response
    
    def test_scanner_initialization(self, scanner):
        """Test scanner initialization"""
        assert scanner is not None
        assert len(scanner.payloads) > 0
        assert len(scanner.error_patterns) > 0
        assert scanner.logger is not None
    
    def test_payload_loading(self, scanner):
        """Test SQL injection payload loading"""
        payloads = scanner.payloads
        
        # Check that we have different types of payloads
        payload_types = {payload['type'] for payload in payloads}
        expected_types = {'error_based', 'boolean_based', 'union_based', 'time_based'}
        
        assert expected_types.issubset(payload_types)
        
        # Check payload structure
        for payload in payloads:
            assert 'name' in payload
            assert 'payload' in payload
            assert 'type' in payload
            assert 'risk' in payload
            assert 'description' in payload
    
    def test_extract_parameters(self, scanner):
        """Test parameter extraction from URL"""
        # Test URL with parameters
        url_with_params = "http://example.com/test?id=1&name=test&category=web"
        params = scanner._extract_parameters(url_with_params)
        
        assert params == {'id': '1', 'name': 'test', 'category': 'web'}
        
        # Test URL without parameters
        url_without_params = "http://example.com/test"
        params = scanner._extract_parameters(url_without_params)
        
        assert params == {}
        
        # Test invalid URL
        invalid_url = "not-a-url"
        params = scanner._extract_parameters(invalid_url)
        
        assert params == {}
    
    def test_build_url_with_param(self, scanner):
        """Test URL building with parameters"""
        base_url = "http://example.com/test?id=1&name=test"
        
        # Test parameter replacement
        new_url = scanner._build_url_with_param(base_url, "id", "malicious_payload")
        assert "malicious_payload" in new_url
        assert "id=" in new_url
        
        # Test parameter addition
        new_url = scanner._build_url_with_param(base_url, "new_param", "value")
        assert "new_param=value" in new_url
    
    def test_detect_error_based(self, scanner):
        """Test error-based SQL injection detection"""
        baseline_response = {
            'content': 'Normal response',
            'status_code': 200,
            'content_length': 15
        }
        
        # Test with SQL error in response
        malicious_response = {
            'content': 'You have an error in your SQL syntax',
            'status_code': 500,
            'content_length': 36
        }
        
        is_vulnerable, confidence, evidence = scanner._detect_error_based(
            baseline_response, malicious_response
        )
        
        assert is_vulnerable is True
        assert confidence > 0.8
        assert len(evidence['detected_errors']) > 0
        
        # Test without SQL error
        normal_response = {
            'content': 'Normal response without errors',
            'status_code': 200,
            'content_length': 30
        }
        
        is_vulnerable, confidence, evidence = scanner._detect_error_based(
            baseline_response, normal_response
        )
        
        assert is_vulnerable is False
        assert confidence == 0.0
    
    def test_detect_boolean_based(self, scanner):
        """Test boolean-based SQL injection detection"""
        baseline_response = {
            'content': 'User: admin',
            'status_code': 200,
            'content_length': 11
        }
        
        # Test OR-based payload (should return more content)
        or_payload_info = {
            'payload': "1' OR '1'='1",
            'type': 'boolean_based'
        }
        
        or_response = {
            'content': 'User: admin\nUser: test\nUser: guest',
            'status_code': 200,
            'content_length': 33  # Much longer response
        }
        
        is_vulnerable, confidence, evidence = scanner._detect_boolean_based(
            baseline_response, or_response, or_payload_info
        )

        print(f"Debug: length_ratio={evidence.get('length_ratio', 'N/A')}, length_diff={evidence.get('length_difference', 'N/A')}")
        print(f"Debug: is_vulnerable={is_vulnerable}, confidence={confidence}")

        assert is_vulnerable is True
        assert confidence > 0.6  # Lower threshold for test
        assert evidence['length_ratio'] > 2.0  # 33/11 = 3.0
        
        # Test AND false payload (should return less content)
        and_false_payload_info = {
            'payload': "1' AND '1'='2",
            'type': 'boolean_based'
        }
        
        and_false_response = {
            'content': '',
            'status_code': 200,
            'content_length': 0
        }
        
        is_vulnerable, confidence, evidence = scanner._detect_boolean_based(
            baseline_response, and_false_response, and_false_payload_info
        )
        
        assert is_vulnerable is True
        assert confidence > 0.6
        assert evidence['length_ratio'] < 0.5
    
    def test_detect_union_based(self, scanner):
        """Test union-based SQL injection detection"""
        baseline_response = {
            'content': 'User: admin',
            'status_code': 200,
            'content_length': 11
        }
        
        # Test union payload with database information
        union_payload_info = {
            'payload': "1' UNION SELECT null,version()--",
            'type': 'union_based'
        }
        
        union_response = {
            'content': 'User: admin\nUser: 5.7.34-mysql',
            'status_code': 200,
            'content_length': 28
        }
        
        is_vulnerable, confidence, evidence = scanner._detect_union_based(
            baseline_response, union_response, union_payload_info
        )
        
        assert is_vulnerable is True
        assert confidence > 0.8
        assert len(evidence['detected_data']) > 0
        assert evidence['data_extracted'] is True
    
    def test_detect_time_based(self, scanner):
        """Test time-based SQL injection detection"""
        baseline_response = {
            'content': 'User: admin',
            'status_code': 200,
            'response_time': 0.1,
            'content_length': 11
        }
        
        # Test with significant time delay
        time_based_response = {
            'content': 'User: admin',
            'status_code': 200,
            'response_time': 5.2,  # 5+ second delay
            'content_length': 11
        }
        
        is_vulnerable, confidence, evidence = scanner._detect_time_based(
            baseline_response, time_based_response
        )
        
        assert is_vulnerable is True
        assert confidence > 0.8
        assert evidence['time_delay_detected'] is True
        assert evidence['time_difference'] > 4.0
        
        # Test without significant delay
        normal_response = {
            'content': 'User: admin',
            'status_code': 200,
            'response_time': 0.2,
            'content_length': 11
        }
        
        is_vulnerable, confidence, evidence = scanner._detect_time_based(
            baseline_response, normal_response
        )
        
        assert is_vulnerable is False
        assert confidence == 0.0
    
    def test_map_injection_type_to_vuln_type(self, scanner):
        """Test injection type mapping"""
        assert scanner._map_injection_type_to_vuln_type('error_based') == VulnerabilityType.ERROR_BASED_SQLI.value
        assert scanner._map_injection_type_to_vuln_type('union_based') == VulnerabilityType.UNION_BASED_SQLI.value
        assert scanner._map_injection_type_to_vuln_type('boolean_based') == VulnerabilityType.BOOLEAN_BLIND_SQLI.value
        assert scanner._map_injection_type_to_vuln_type('time_based') == VulnerabilityType.TIME_BASED_SQLI.value
        assert scanner._map_injection_type_to_vuln_type('unknown') == VulnerabilityType.SQL_INJECTION.value
    
    @pytest.mark.asyncio
    async def test_make_baseline_request(self, scanner):
        """Test baseline request making"""
        with patch.object(scanner, '_make_request', new_callable=AsyncMock) as mock_request:
            mock_response = Mock()
            mock_response.text = "Normal response"
            mock_response.status_code = 200
            mock_response.headers = {"Content-Type": "text/html"}
            mock_request.return_value = mock_response
            
            result = await scanner._make_baseline_request(
                "http://example.com/test?id=1", "id", "1"
            )
            
            assert result is not None
            assert result['content'] == "Normal response"
            assert result['status_code'] == 200
            assert 'response_time' in result
            assert 'content_length' in result
    
    @pytest.mark.asyncio
    async def test_make_malicious_request(self, scanner):
        """Test malicious request making"""
        with patch.object(scanner, '_make_request', new_callable=AsyncMock) as mock_request:
            mock_response = Mock()
            mock_response.text = "Error response"
            mock_response.status_code = 500
            mock_response.headers = {"Content-Type": "text/html"}
            mock_request.return_value = mock_response
            
            result = await scanner._make_malicious_request(
                "http://example.com/test?id=1", "id", "1'"
            )
            
            assert result is not None
            assert result['content'] == "Error response"
            assert result['status_code'] == 500
            assert result['payload'] == "1'"
            assert 'response_time' in result
            assert 'content_length' in result
    
    @pytest.mark.asyncio
    async def test_scan_no_parameters(self, scanner):
        """Test scan with URL that has no parameters"""
        result = await scanner.scan("http://example.com/test")
        
        assert result['target_url'] == "http://example.com/test"
        assert result['scan_type'] == 'sql_injection'
        assert result['scan_summary']['total_tests'] == 0
        assert result['scan_summary']['vulnerabilities_found'] == 0
        assert len(result['vulnerabilities']) == 0
    
    @pytest.mark.asyncio
    async def test_scan_with_mock_responses(self, scanner):
        """Test full scan with mocked HTTP responses"""
        target_url = "http://example.com/test?id=1"
        
        # Mock the HTTP requests
        with patch.object(scanner, '_make_request', new_callable=AsyncMock) as mock_request:
            # First call (baseline) - normal response
            # Second call (malicious) - error response
            mock_responses = [
                Mock(text="Normal response", status_code=200, headers={}),
                Mock(text="You have an error in your SQL syntax", status_code=500, headers={})
            ]
            mock_request.side_effect = mock_responses * 10  # Repeat for multiple payloads
            
            result = await scanner.scan(target_url)
            
            assert result['target_url'] == target_url
            assert result['scan_type'] == 'sql_injection'
            assert result['scan_summary']['total_tests'] > 0
            assert 'scan_metadata' in result
            assert 'duration' in result['scan_metadata']
