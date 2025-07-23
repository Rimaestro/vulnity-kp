"""
Scanner Output Validation Tests
Tests that validate the scanner produces realistic and accurate output
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from app.services.scanner.sql_injection import SQLInjectionScanner


class TestScannerOutputValidation:
    """Test that scanner produces realistic and accurate output"""
    
    @pytest.mark.asyncio
    async def test_scanner_output_structure(self):
        """Test that scanner returns properly structured output"""

        scanner = SQLInjectionScanner()
        test_url = "http://localhost/dvwa/vulnerabilities/sqli/?id=1"
        
        results = await scanner.scan(test_url)
        
        # Verify basic structure
        assert isinstance(results, dict), "Results should be a dictionary"
        
        # Check required keys
        required_keys = ['target_url', 'scan_type', 'vulnerabilities', 'scan_summary', 'scan_metadata']
        for key in required_keys:
            assert key in results, f"Results should contain '{key}'"
        
        # Verify scan_summary structure
        summary = results['scan_summary']
        summary_keys = ['total_tests', 'vulnerabilities_found', 'critical_count', 'high_count', 'medium_count']
        for key in summary_keys:
            assert key in summary, f"Scan summary should contain '{key}'"
            assert isinstance(summary[key], int), f"'{key}' should be an integer"
        
        # Verify scan_metadata structure
        metadata = results['scan_metadata']
        metadata_keys = ['start_time', 'end_time', 'duration', 'parameters_tested']
        for key in metadata_keys:
            assert key in metadata, f"Scan metadata should contain '{key}'"
        
        print(f"✅ Scanner output structure is valid")
        print(f"   - Target URL: {results['target_url']}")
        print(f"   - Scan type: {results['scan_type']}")
        print(f"   - Vulnerabilities found: {summary['vulnerabilities_found']}")
        print(f"   - Duration: {metadata['duration']:.2f}s")
    
    @pytest.mark.asyncio
    async def test_vulnerability_output_structure(self):
        """Test that vulnerability objects have proper structure"""

        scanner = SQLInjectionScanner()
        test_url = "http://localhost/dvwa/vulnerabilities/sqli/?id=1"
        
        results = await scanner.scan(test_url)
        
        if results['scan_summary']['vulnerabilities_found'] > 0:
            vuln = results['vulnerabilities'][0]
            
            # Check required vulnerability fields
            required_fields = [
                'title', 'description', 'vulnerability_type', 'risk', 
                'endpoint', 'parameter', 'method', 'payload', 'confidence',
                'evidence', 'request_data', 'response_data'
            ]
            
            for field in required_fields:
                assert field in vuln, f"Vulnerability should contain '{field}'"
            
            # Verify field types and values
            assert isinstance(vuln['title'], str), "Title should be string"
            assert isinstance(vuln['confidence'], float), "Confidence should be float"
            assert 0.0 <= vuln['confidence'] <= 1.0, "Confidence should be between 0 and 1"
            assert vuln['risk'] in ['low', 'medium', 'high', 'critical'], "Risk should be valid level"
            assert vuln['method'] in ['GET', 'POST'], "Method should be valid HTTP method"
            
            print(f"✅ Vulnerability output structure is valid")
            print(f"   - Title: {vuln['title']}")
            print(f"   - Type: {vuln['vulnerability_type']}")
            print(f"   - Risk: {vuln['risk']}")
            print(f"   - Confidence: {vuln['confidence']:.2f}")
            print(f"   - Payload: {vuln['payload']}")
    
    @pytest.mark.asyncio
    async def test_realistic_payload_testing(self):
        """Test that scanner tests realistic SQL injection payloads"""
        
        scanner = SQLInjectionScanner()
        payloads = scanner.payloads
        
        # Verify we have DVWA-compatible payloads
        payload_strings = [p['payload'] for p in payloads]
        
        # Check for essential payload types
        assert any("'" in p for p in payload_strings), "Should have error-inducing payloads"
        assert any("UNION SELECT" in p for p in payload_strings), "Should have union-based payloads"
        assert any("OR" in p and "1'='1" in p for p in payload_strings), "Should have boolean OR payloads"
        assert any("SLEEP(" in p for p in payload_strings), "Should have time-based payloads"
        
        # Verify payload metadata
        for payload in payloads:
            assert 'name' in payload, "Payload should have name"
            assert 'payload' in payload, "Payload should have payload string"
            assert 'type' in payload, "Payload should have type"
            assert 'risk' in payload, "Payload should have risk level"
            assert 'description' in payload, "Payload should have description"
        
        print(f"✅ Realistic payloads are configured")
        print(f"   - Total payloads: {len(payloads)}")
        print(f"   - Payload types: {set(p['type'] for p in payloads)}")
        
        # Show sample payloads
        print(f"   - Sample payloads:")
        for i, payload in enumerate(payloads[:3]):
            print(f"     {i+1}. {payload['name']}: {payload['payload']}")
    
    @pytest.mark.asyncio
    async def test_error_pattern_detection(self):
        """Test that scanner can detect realistic error patterns"""
        
        scanner = SQLInjectionScanner()
        error_patterns = scanner.error_patterns
        
        # Test with realistic DVWA error content
        dvwa_error_content = """
        <br />
        <b>Warning</b>: mysql_fetch_array() expects parameter 1 to be resource, boolean given in <b>/var/www/html/dvwa/vulnerabilities/sqli/source/low.php</b> on line <b>15</b><br />
        <br />
        <b>Warning</b>: mysql_num_rows() expects parameter 1 to be resource, boolean given in <b>/var/www/html/dvwa/vulnerabilities/sqli/source/low.php</b> on line <b>16</b><br />
        """
        
        # Test error detection
        detected_errors = []
        for pattern in error_patterns:
            if pattern.lower() in dvwa_error_content.lower():
                detected_errors.append(pattern)
        
        assert len(detected_errors) > 0, "Should detect DVWA error patterns"
        
        print(f"✅ Error pattern detection works")
        print(f"   - Total patterns: {len(error_patterns)}")
        print(f"   - Detected in DVWA content: {detected_errors}")
    
    @pytest.mark.asyncio
    async def test_realistic_scan_timing(self):
        """Test that scan timing is realistic"""

        scanner = SQLInjectionScanner()
        test_url = "http://localhost/dvwa/vulnerabilities/sqli/?id=1"
        
        import time
        start_time = time.time()
        results = await scanner.scan(test_url)
        actual_duration = time.time() - start_time
        
        reported_duration = results['scan_metadata']['duration']
        
        # Verify timing is realistic
        assert reported_duration > 0, "Duration should be positive"
        assert abs(actual_duration - reported_duration) < 5, "Reported duration should be close to actual"
        
        # For real scanning, duration should be reasonable (not too fast, not too slow)
        assert 1 < reported_duration < 60, "Scan duration should be realistic (1-60 seconds)"
        
        print(f"✅ Scan timing is realistic")
        print(f"   - Reported duration: {reported_duration:.2f}s")
        print(f"   - Actual duration: {actual_duration:.2f}s")
        print(f"   - Tests performed: {results['scan_summary']['total_tests']}")
    
    @pytest.mark.asyncio
    async def test_confidence_scoring_realism(self):
        """Test that confidence scoring is realistic"""

        scanner = SQLInjectionScanner()
        test_url = "http://localhost/dvwa/vulnerabilities/sqli/?id=1"
        
        results = await scanner.scan(test_url)
        
        if results['scan_summary']['vulnerabilities_found'] > 0:
            for vuln in results['vulnerabilities']:
                confidence = vuln['confidence']
                
                # Confidence should be realistic
                assert 0.0 <= confidence <= 1.0, "Confidence should be between 0 and 1"
                
                # For real vulnerabilities, confidence should not be too low
                assert confidence >= 0.5, "Detected vulnerabilities should have reasonable confidence"
                
                # High confidence should correlate with high risk
                if confidence >= 0.9:
                    assert vuln['risk'] in ['high', 'critical'], "High confidence should mean high risk"
                
                print(f"✅ Vulnerability confidence: {confidence:.2f} (Risk: {vuln['risk']})")
    
    @pytest.mark.asyncio
    async def test_evidence_collection_realism(self):
        """Test that evidence collection is realistic and useful"""

        scanner = SQLInjectionScanner()
        test_url = "http://localhost/dvwa/vulnerabilities/sqli/?id=1"
        
        results = await scanner.scan(test_url)
        
        if results['scan_summary']['vulnerabilities_found'] > 0:
            for vuln in results['vulnerabilities']:
                evidence = vuln['evidence']
                request_data = vuln['request_data']
                response_data = vuln['response_data']
                
                # Evidence should contain useful information
                assert isinstance(evidence, dict), "Evidence should be a dictionary"
                assert len(evidence) > 0, "Evidence should not be empty"
                
                # Request data should be complete
                assert 'url' in request_data, "Request data should contain URL"
                assert 'parameter' in request_data, "Request data should contain parameter"
                assert 'payload' in request_data, "Request data should contain payload"
                
                # Response data should be informative
                assert 'baseline_status' in response_data, "Response data should contain baseline status"
                assert 'malicious_status' in response_data, "Response data should contain malicious status"
                
                print(f"✅ Evidence collection is comprehensive")
                print(f"   - Evidence keys: {list(evidence.keys())}")
                print(f"   - Request data keys: {list(request_data.keys())}")
                print(f"   - Response data keys: {list(response_data.keys())}")
    
    def test_dvwa_compatibility_summary(self):
        """Summary test showing DVWA compatibility"""
        
        scanner = SQLInjectionScanner()
        
        # Check payload compatibility
        payloads = scanner.payloads
        dvwa_compatible_payloads = 0
        
        for payload in payloads:
            # Count payloads that would work against DVWA
            if any(pattern in payload['payload'] for pattern in ["'", "UNION", "OR", "SLEEP"]):
                dvwa_compatible_payloads += 1
        
        # Check error pattern compatibility
        error_patterns = scanner.error_patterns
        dvwa_compatible_patterns = 0
        
        dvwa_errors = ["mysql_fetch_array", "mysql_num_rows", "SQL syntax", "Warning: mysql"]
        for pattern in error_patterns:
            if any(error in pattern for error in dvwa_errors):
                dvwa_compatible_patterns += 1
        
        print(f"\n🎯 DVWA COMPATIBILITY SUMMARY:")
        print(f"   ✅ Total payloads: {len(payloads)}")
        print(f"   ✅ DVWA-compatible payloads: {dvwa_compatible_payloads}")
        print(f"   ✅ Total error patterns: {len(error_patterns)}")
        print(f"   ✅ DVWA-compatible patterns: {dvwa_compatible_patterns}")
        print(f"   ✅ Payload compatibility: {(dvwa_compatible_payloads/len(payloads)*100):.1f}%")
        print(f"   ✅ Pattern compatibility: {(dvwa_compatible_patterns/len(error_patterns)*100):.1f}%")
        
        # Assertions for minimum compatibility
        assert dvwa_compatible_payloads >= len(payloads) * 0.8, "Should have 80%+ DVWA-compatible payloads"
        assert dvwa_compatible_patterns >= len(error_patterns) * 0.5, "Should have 50%+ DVWA-compatible patterns"
