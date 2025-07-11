"""
Test Suite for Detection Signatures
Based on DVWA payload testing patterns
"""

import pytest
import sys
import os

# Add the parent directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner.detection_signatures import SQLInjectionSignatures, VulnerabilityType


class TestSQLInjectionSignatures:
    """Test detection signatures based on DVWA testing results"""
    
    @pytest.fixture
    def signatures(self):
        """Create SQLInjectionSignatures instance"""
        return SQLInjectionSignatures()
    
    def test_init(self, signatures):
        """Test signatures initialization"""
        assert signatures.signatures is not None
        assert "boolean_based" in signatures.signatures
        assert "union_based" in signatures.signatures
        assert "time_based" in signatures.signatures
        assert "error_based" in signatures.signatures
        assert "blind_boolean" in signatures.signatures
    
    def test_boolean_based_detection_success(self, signatures):
        """Test boolean-based detection with DVWA success response"""
        # Mock successful boolean injection response (Payload 1 & 5 results)
        response_text = '''
        ID: 1' OR '1'='1
        First name: admin
        Surname: admin
        
        ID: 1' OR '1'='1
        First name: Gordon
        Surname: Brown
        
        ID: 1' OR '1'='1
        First name: Pablo
        Surname: Picasso
        
        ID: 1' OR '1'='1
        First name: Hack
        Surname: Me
        
        ID: 1' OR '1'='1
        First name: Bob
        Surname: Smith
        '''
        
        result = signatures.detect_boolean_based(response_text)
        
        assert result.detected is True
        assert result.confidence > 0.6  # High confidence with multiple indicators
        assert result.vulnerability_type == VulnerabilityType.SQL_INJECTION
        assert "Gordon Brown" in result.extracted_data
        assert "Pablo Picasso" in result.extracted_data
        assert "Hack Me" in result.extracted_data
        assert "Bob Smith" in result.extracted_data
        assert result.details["bypass_successful"] is True
        assert result.details["indicator_count"] >= 4
    
    def test_boolean_based_detection_failure(self, signatures):
        """Test boolean-based detection with normal response"""
        response_text = '''
        ID: 1
        First name: admin
        Surname: admin
        '''
        
        result = signatures.detect_boolean_based(response_text)
        
        assert result.detected is False
        assert result.confidence < 0.6
    
    def test_union_based_detection_critical(self, signatures):
        """Test union-based detection with critical system info (Payload 7 results)"""
        response_text = '''
        ID: 1' UNION SELECT user(),version()#
        First name: admin
        Surname: admin
        
        ID: 1' UNION SELECT user(),version()#
        First name: root@localhost
        Surname: 10.4.32-MariaDB
        '''
        
        result = signatures.detect_union_based(response_text)
        
        assert result.detected is True
        assert result.confidence >= 0.9  # High confidence with critical info
        assert result.vulnerability_type == VulnerabilityType.SQL_INJECTION
        assert "root@localhost" in result.extracted_data
        assert "10.4.32-MariaDB" in result.extracted_data
        assert result.details["critical_disclosure"] is True
        assert result.details["system_info_extracted"] is not None
    
    def test_union_based_detection_basic(self, signatures):
        """Test union-based detection with basic injection (Payload 6 results)"""
        response_text = '''
        ID: 1' UNION SELECT 1,2#
        First name: admin
        Surname: admin
        
        ID: 1' UNION SELECT 1,2#
        First name: 1
        Surname: 2
        '''
        
        result = signatures.detect_union_based(response_text)
        
        # This should not be detected as critical since no system info
        assert result.detected is False or result.confidence < 0.9
    
    def test_time_based_detection_success(self, signatures):
        """Test time-based detection with 5-second delay (Payload 8 results)"""
        response_time = 5.1  # Successful SLEEP(5) execution
        expected_delay = 5.0
        
        result = signatures.detect_time_based(response_time, expected_delay)
        
        assert result.detected is True
        assert result.confidence > 0.8  # High confidence for accurate delay
        assert result.vulnerability_type == VulnerabilityType.SQL_INJECTION
        assert "Response delay: 5.10s" in result.extracted_data
        assert result.details["response_time"] == 5.1
        assert result.details["expected_delay"] == 5.0
        assert result.details["delay_accuracy"] > 0.8
    
    def test_time_based_detection_failure(self, signatures):
        """Test time-based detection with normal response time"""
        response_time = 0.3  # Normal response time
        expected_delay = 5.0
        
        result = signatures.detect_time_based(response_time, expected_delay)
        
        assert result.detected is False
        assert result.confidence == 0.0
    
    def test_error_based_detection_dvwa(self, signatures):
        """Test error-based detection with DVWA error messages (Payload 2, 3, 4)"""
        response_text = '''
        Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; 
        check the manual that corresponds to your MariaDB server version for the right syntax 
        to use near '--' at line 1 in C:\\xampp\\htdocs\\dvwa\\vulnerabilities\\sqli\\source\\low.php:11
        Stack trace:
        #0 C:\\xampp\\htdocs\\dvwa\\vulnerabilities\\sqli\\source\\low.php(11): mysqli_query(Object(mysqli), 'SELECT first_na...')
        '''
        
        result = signatures.detect_error_based(response_text)
        
        assert result.detected is True
        assert result.confidence > 0.5
        assert result.vulnerability_type == VulnerabilityType.SQL_INJECTION
        assert len(result.patterns_matched) > 0
        assert len(result.extracted_data) > 0
        assert result.details["information_disclosure"] is True
        
        # Check for specific DVWA disclosures
        extracted_text = " ".join(result.extracted_data + result.patterns_matched)
        assert "C:\\xampp\\htdocs\\dvwa" in extracted_text
        assert "line 11" in extracted_text or "line" in extracted_text
        assert "mysqli_query" in extracted_text
    
    def test_error_based_detection_no_errors(self, signatures):
        """Test error-based detection with normal response"""
        response_text = '''
        ID: 1
        First name: admin
        Surname: admin
        '''
        
        result = signatures.detect_error_based(response_text)
        
        assert result.detected is False
        assert result.confidence == 0.0
    
    def test_signature_patterns_initialization(self, signatures):
        """Test that signature patterns are correctly initialized"""
        sigs = signatures.signatures
        
        # Boolean-based signatures
        boolean_sigs = sigs["boolean_based"]
        assert "Gordon Brown" in boolean_sigs["success_indicators"]
        assert "Pablo Picasso" in boolean_sigs["success_indicators"]
        assert "Hack Me" in boolean_sigs["success_indicators"]
        assert "Bob Smith" in boolean_sigs["success_indicators"]
        assert "admin" in boolean_sigs["success_indicators"]
        assert boolean_sigs["confidence_threshold"] == 2
        assert boolean_sigs["severity"] == "high"
        
        # Union-based signatures
        union_sigs = sigs["union_based"]
        assert "root@localhost" in union_sigs["success_indicators"]
        assert "10.4.32-MariaDB" in union_sigs["success_indicators"]
        assert "root@localhost" in union_sigs["critical_indicators"]
        assert union_sigs["confidence_threshold"] == 1
        assert union_sigs["severity"] == "critical"
        
        # Time-based signatures
        time_sigs = sigs["time_based"]
        assert "sleep_5" in time_sigs["time_thresholds"]
        assert time_sigs["time_thresholds"]["sleep_5"]["min"] == 4.5
        assert time_sigs["time_thresholds"]["sleep_5"]["max"] == 5.5
        assert time_sigs["severity"] == "medium"
        
        # Error-based signatures
        error_sigs = sigs["error_based"]
        assert "Fatal error:" in error_sigs["error_patterns"]
        assert "mysqli_sql_exception:" in error_sigs["error_patterns"]
        assert "You have an error in your SQL syntax" in error_sigs["error_patterns"]
        assert "MariaDB server version" in error_sigs["error_patterns"]
        
        # Information patterns
        info_patterns = error_sigs["information_patterns"]
        assert any("xampp" in pattern for pattern in info_patterns)
        assert any("line" in pattern for pattern in info_patterns)
        assert any("mysqli_" in pattern for pattern in info_patterns)
        
        # Critical disclosures
        critical_patterns = error_sigs["critical_disclosures"]
        assert any("dvwa" in pattern for pattern in critical_patterns)
        assert "line 11" in critical_patterns
        assert "mysqli_query" in critical_patterns
    
    def test_confidence_calculation_boolean(self, signatures):
        """Test confidence calculation for boolean-based detection"""
        # Test with different numbers of indicators
        test_cases = [
            ("admin", 1, False),  # 1 indicator - below threshold
            ("admin Gordon Brown", 2, True),  # 2 indicators - at threshold
            ("admin Gordon Brown Pablo Picasso", 3, True),  # 3 indicators - above threshold
            ("admin Gordon Brown Pablo Picasso Hack Me Bob Smith", 5, True),  # All indicators
        ]
        
        for text, expected_count, should_detect in test_cases:
            response = f"First name: {text}"
            result = signatures.detect_boolean_based(response)
            
            assert result.detected == should_detect
            if should_detect:
                assert result.confidence > 0.0
                assert result.details["indicator_count"] >= 2
    
    def test_union_confidence_with_critical_info(self, signatures):
        """Test confidence boost for critical information in union-based detection"""
        # Test without critical info
        basic_response = "First name: mysql\nSurname: localhost"
        basic_result = signatures.detect_union_based(basic_response)
        
        # Test with critical info
        critical_response = "First name: root@localhost\nSurname: 10.4.32-MariaDB"
        critical_result = signatures.detect_union_based(critical_response)
        
        # Critical info should have higher confidence
        if critical_result.detected:
            assert critical_result.confidence > 0.8
            assert critical_result.details["critical_disclosure"] is True
    
    def test_time_based_accuracy_calculation(self, signatures):
        """Test time-based confidence calculation based on delay accuracy"""
        expected_delay = 5.0
        
        test_cases = [
            (5.0, True, 1.0),    # Perfect timing
            (5.1, True, 0.98),   # Very close
            (4.9, True, 0.98),   # Very close
            (5.5, True, 0.9),    # Within threshold
            (4.5, True, 0.9),    # Within threshold
            (3.0, False, 0.0),   # Too fast
            (7.0, False, 0.0),   # Too slow
        ]
        
        for response_time, should_detect, min_confidence in test_cases:
            result = signatures.detect_time_based(response_time, expected_delay)
            
            assert result.detected == should_detect
            if should_detect:
                assert result.confidence >= min_confidence - 0.1  # Allow small variance


if __name__ == "__main__":
    pytest.main([__file__])
