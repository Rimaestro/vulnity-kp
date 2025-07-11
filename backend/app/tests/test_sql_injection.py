"""
Test Suite for SQL Injection Scanner
Based on DVWA payload testing results (70% success rate)
"""

import pytest
import requests
from unittest.mock import Mock, patch
import sys
import os
import time

# Add the parent directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner.sql_injection import SQLInjectionScanner, SQLInjectionType, Severity


class TestSQLInjectionScanner:
    """Test cases based on DVWA payload testing results"""
    
    @pytest.fixture
    def mock_session(self):
        """Mock requests session"""
        return Mock(spec=requests.Session)
    
    @pytest.fixture
    def scanner(self, mock_session):
        """Create SQLInjectionScanner instance"""
        return SQLInjectionScanner(mock_session)
    
    def test_init(self, scanner, mock_session):
        """Test scanner initialization"""
        assert scanner.session == mock_session
        assert scanner.timeout == 30
        assert scanner.comment_syntax == "#"  # Based on testing results
        assert SQLInjectionType.BOOLEAN_BASED in scanner.payloads
        assert SQLInjectionType.UNION_BASED in scanner.payloads
    
    def test_payload_initialization(self, scanner):
        """Test that payloads are correctly initialized from testing results"""
        # Boolean-based payloads (successful from testing)
        boolean_payloads = scanner.payloads[SQLInjectionType.BOOLEAN_BASED]
        assert "1' OR '1'='1" in boolean_payloads  # Payload 1: ✅ BERHASIL
        assert "1' OR 1=1#" in boolean_payloads    # Payload 5: ✅ BERHASIL
        
        # Union-based payloads (successful from testing)
        union_payloads = scanner.payloads[SQLInjectionType.UNION_BASED]
        assert "1' UNION SELECT 1,2#" in union_payloads                # Payload 6: ✅ BERHASIL
        assert "1' UNION SELECT user(),version()#" in union_payloads   # Payload 7: ✅ BERHASIL
        
        # Time-based payloads (successful from testing)
        time_payloads = scanner.payloads[SQLInjectionType.TIME_BASED]
        assert "1' AND SLEEP(5)#" in time_payloads  # Payload 8: ✅ BERHASIL
        
        # Blind boolean payloads (successful from testing)
        blind_payloads = scanner.payloads[SQLInjectionType.BLIND_BOOLEAN]
        assert "1' AND 1=1#" in blind_payloads  # Payload 9: ✅ BERHASIL
        assert "1' AND 1=2#" in blind_payloads  # Payload 10: ✅ BERHASIL
    
    def test_detection_signatures_initialization(self, scanner):
        """Test detection signatures based on testing results"""
        signatures = scanner.detection_signatures
        
        # Boolean success indicators from DVWA testing
        boolean_indicators = signatures["boolean_success"]
        assert "Gordon Brown" in boolean_indicators
        assert "Pablo Picasso" in boolean_indicators
        assert "Hack Me" in boolean_indicators
        assert "Bob Smith" in boolean_indicators
        assert "admin" in boolean_indicators
        
        # Union success indicators from Payload 7 results
        union_indicators = signatures["union_success"]
        assert "root@localhost" in union_indicators    # From Payload 7
        assert "10.4.32-MariaDB" in union_indicators   # From Payload 7
    
    @patch('requests.Session.get')
    def test_boolean_based_detection_success(self, mock_get, scanner):
        """Test boolean-based SQL injection detection (Payload 1 & 5 results)"""
        # Mock successful boolean injection response (multiple users)
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '''
        ID: 1' OR '1'='1
        First name: admin
        Surname: admin
        
        ID: 1' OR '1'='1
        First name: Gordon
        Surname: Brown
        
        ID: 1' OR '1'='1
        First name: Pablo
        Surname: Picasso
        '''
        mock_response.elapsed = Mock()
        mock_response.elapsed.total_seconds.return_value = 0.5
        mock_get.return_value = mock_response
        
        url = "http://localhost/dvwa/vulnerabilities/sqli/"
        results = scanner.scan_parameter(url, "id")
        
        # Should detect boolean-based injection
        boolean_results = [r for r in results if r.injection_type == SQLInjectionType.BOOLEAN_BASED]
        assert len(boolean_results) > 0
        
        result = boolean_results[0]
        assert result.vulnerable is True
        assert result.severity == Severity.HIGH
        assert "Gordon" in str(result.extracted_data)
        assert "Pablo" in str(result.extracted_data)
    
    @patch('requests.Session.get')
    def test_union_based_detection_success(self, mock_get, scanner):
        """Test union-based SQL injection detection (Payload 7 results)"""
        # Mock successful union injection response with system info
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '''
        ID: 1' UNION SELECT user(),version()#
        First name: admin
        Surname: admin
        
        ID: 1' UNION SELECT user(),version()#
        First name: root@localhost
        Surname: 10.4.32-MariaDB
        '''
        mock_response.elapsed = Mock()
        mock_response.elapsed.total_seconds.return_value = 0.3
        mock_get.return_value = mock_response
        
        url = "http://localhost/dvwa/vulnerabilities/sqli/"
        results = scanner.scan_parameter(url, "id")
        
        # Should detect union-based injection
        union_results = [r for r in results if r.injection_type == SQLInjectionType.UNION_BASED]
        assert len(union_results) > 0
        
        result = union_results[0]
        assert result.vulnerable is True
        assert result.severity == Severity.CRITICAL  # Critical due to system info
        assert "root@localhost" in str(result.extracted_data)
        assert "10.4.32-MariaDB" in str(result.extracted_data)
    
    @patch('requests.Session.get')
    def test_time_based_detection_success(self, mock_get, scanner):
        """Test time-based SQL injection detection (Payload 8 results)"""
        # Mock time-based injection response with delay
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "ID: 1' AND SLEEP(5)#\nFirst name: admin\nSurname: admin"
        mock_response.elapsed = Mock()
        mock_response.elapsed.total_seconds.return_value = 5.1  # 5 second delay
        
        # Mock the time delay in _inject_payload
        with patch('time.time', side_effect=[0, 5.1]):
            mock_get.return_value = mock_response
            
            url = "http://localhost/dvwa/vulnerabilities/sqli/"
            results = scanner.scan_parameter(url, "id")
        
        # Should detect time-based injection
        time_results = [r for r in results if r.injection_type == SQLInjectionType.TIME_BASED]
        assert len(time_results) > 0
        
        result = time_results[0]
        assert result.vulnerable is True
        assert result.severity == Severity.MEDIUM
        assert result.response_time >= 4.5
    
    @patch('requests.Session.get')
    def test_blind_boolean_true_condition(self, mock_get, scanner):
        """Test blind boolean injection - true condition (Payload 9)"""
        # Mock true condition response (should return data)
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "ID: 1' AND 1=1#\nFirst name: admin\nSurname: admin"
        mock_response.elapsed = Mock()
        mock_response.elapsed.total_seconds.return_value = 0.2
        mock_get.return_value = mock_response
        
        url = "http://localhost/dvwa/vulnerabilities/sqli/"
        results = scanner.scan_parameter(url, "id")
        
        # Should detect blind boolean injection
        blind_results = [r for r in results if r.injection_type == SQLInjectionType.BLIND_BOOLEAN]
        assert len(blind_results) > 0
        
        # Find the true condition result
        true_results = [r for r in blind_results if "1=1" in r.payload]
        assert len(true_results) > 0
        
        result = true_results[0]
        assert result.vulnerable is True
        assert result.severity == Severity.MEDIUM
    
    @patch('requests.Session.get')
    def test_blind_boolean_false_condition(self, mock_get, scanner):
        """Test blind boolean injection - false condition (Payload 10)"""
        # Mock false condition response (should return no data)
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = ""  # Empty response for false condition
        mock_response.elapsed = Mock()
        mock_response.elapsed.total_seconds.return_value = 0.2
        mock_get.return_value = mock_response
        
        url = "http://localhost/dvwa/vulnerabilities/sqli/"
        results = scanner.scan_parameter(url, "id")
        
        # Should detect blind boolean injection
        blind_results = [r for r in results if r.injection_type == SQLInjectionType.BLIND_BOOLEAN]
        assert len(blind_results) > 0
        
        # Find the false condition result
        false_results = [r for r in blind_results if "1=2" in r.payload]
        assert len(false_results) > 0
        
        result = false_results[0]
        assert result.vulnerable is True
        assert result.severity == Severity.MEDIUM
    
    @patch('requests.Session.get')
    def test_error_based_detection(self, mock_get, scanner):
        """Test error-based information disclosure (Failed payloads 2, 3, 4)"""
        # Mock error response with information disclosure
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '''
        Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; 
        check the manual that corresponds to your MariaDB server version for the right syntax 
        to use near '--' at line 1 in C:\\xampp\\htdocs\\dvwa\\vulnerabilities\\sqli\\source\\low.php:11
        '''
        mock_response.elapsed = Mock()
        mock_response.elapsed.total_seconds.return_value = 0.1
        mock_get.return_value = mock_response
        
        url = "http://localhost/dvwa/vulnerabilities/sqli/"
        results = scanner.scan_parameter(url, "id")
        
        # Should detect error-based information disclosure
        error_results = [r for r in results if r.injection_type == SQLInjectionType.ERROR_BASED]
        assert len(error_results) > 0
        
        result = error_results[0]
        assert result.vulnerable is True
        assert result.severity == Severity.MEDIUM
        assert len(result.error_disclosure) > 0
    
    def test_comment_syntax_detection(self, scanner):
        """Test comment syntax detection based on testing results"""
        # Hash comment should be detected as working (100% success rate)
        with patch.object(scanner, '_test_payload_success') as mock_test:
            mock_test.side_effect = lambda url, param, payload: "#" in payload
            
            syntax = scanner.detect_comment_syntax("http://test.com", "id")
            assert syntax == "#"
    
    def test_scan_url_with_parameters(self, scanner):
        """Test URL scanning with parameter detection"""
        url = "http://localhost/dvwa/vulnerabilities/sqli/?id=1&name=test"
        
        with patch.object(scanner, 'scan_parameter') as mock_scan:
            mock_scan.return_value = []
            
            results = scanner.scan_url(url)
            
            # Should detect and test both parameters
            assert mock_scan.call_count == 2
            calls = [call[0] for call in mock_scan.call_args_list]
            assert any("id" in str(call) for call in calls)
            assert any("name" in str(call) for call in calls)
    
    def test_generate_report(self, scanner):
        """Test report generation"""
        # Mock vulnerability results
        mock_result = Mock()
        mock_result.injection_type = SQLInjectionType.BOOLEAN_BASED
        mock_result.severity = Severity.HIGH
        mock_result.payload = "1' OR '1'='1"
        mock_result.confidence = 0.9
        mock_result.extracted_data = ["admin", "Gordon Brown"]
        mock_result.error_disclosure = []
        mock_result.details = {"bypass_successful": True}
        
        results = {"id": [mock_result]}
        report = scanner.generate_report(results)
        
        assert report["summary"]["total_parameters"] == 1
        assert report["summary"]["vulnerable_parameters"] == 1
        assert report["summary"]["total_vulnerabilities"] == 1
        assert report["summary"]["severity_breakdown"]["high"] == 1
        assert len(report["vulnerabilities"]) == 1
        assert len(report["recommendations"]) > 0
    
    def test_analyze_response_success(self, scanner):
        """Test response analysis for success detection"""
        # Test boolean success detection
        response_text = "First name: Gordon\nSurname: Brown\nFirst name: Pablo\nSurname: Picasso"
        assert scanner._analyze_response_success("test", response_text, 0.5) is True
        
        # Test union success detection
        response_text = "First name: root@localhost\nSurname: 10.4.32-MariaDB"
        assert scanner._analyze_response_success("test", response_text, 0.3) is True
        
        # Test time-based success detection
        assert scanner._analyze_response_success("test", "normal response", 5.2) is True
        
        # Test failure detection
        assert scanner._analyze_response_success("test", "no indicators", 0.1) is False


if __name__ == "__main__":
    pytest.main([__file__])
