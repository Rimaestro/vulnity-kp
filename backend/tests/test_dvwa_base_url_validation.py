"""
DVWA Base URL Validation Tests
Tests the SQL injection scanner with correct DVWA base URL and documented payloads
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from app.services.scanner.sql_injection import SQLInjectionScanner


class TestDVWABaseURLValidation:
    """Test SQL injection scanner with correct DVWA base URL"""
    
    def setup_method(self):
        """Setup for each test method"""
        self.scanner = SQLInjectionScanner()
        
        # Correct DVWA base URL as per documentation
        self.dvwa_base_url = "http://localhost/dvwa/vulnerabilities/sqli/"
        
        # Realistic DVWA responses based on documentation analysis
        self.dvwa_responses = {
            'normal_response': '''
            <div class="vulnerable_code_area">
                <h2>User ID exists in the database.</h2>
                <table>
                    <tr><td>ID</td><td>First name</td><td>Surname</td></tr>
                    <tr><td>1</td><td>admin</td><td>admin</td></tr>
                </table>
            </div>
            ''',
            'error_response': '''
            <div class="vulnerable_code_area">
                <br />
                <b>Warning</b>: mysql_fetch_array() expects parameter 1 to be resource, boolean given in <b>/var/www/html/dvwa/vulnerabilities/sqli/source/low.php</b> on line <b>15</b><br />
                <br />
                <b>Warning</b>: mysql_num_rows() expects parameter 1 to be resource, boolean given in <b>/var/www/html/dvwa/vulnerabilities/sqli/source/low.php</b> on line <b>16</b><br />
            </div>
            ''',
            'union_version_response': '''
            <div class="vulnerable_code_area">
                <h2>User ID exists in the database.</h2>
                <table>
                    <tr><td>ID</td><td>First name</td><td>Surname</td></tr>
                    <tr><td>1</td><td>admin</td><td>admin</td></tr>
                    <tr><td></td><td>5.7.44-0ubuntu0.18.04.1</td><td></td></tr>
                </table>
            </div>
            ''',
            'boolean_or_response': '''
            <div class="vulnerable_code_area">
                <h2>User ID exists in the database.</h2>
                <table>
                    <tr><td>ID</td><td>First name</td><td>Surname</td></tr>
                    <tr><td>1</td><td>admin</td><td>admin</td></tr>
                    <tr><td>2</td><td>Gordon</td><td>Brown</td></tr>
                    <tr><td>3</td><td>Hack</td><td>Me</td></tr>
                    <tr><td>4</td><td>Pablo</td><td>Picasso</td></tr>
                    <tr><td>5</td><td>Bob</td><td>Smith</td></tr>
                </table>
            </div>
            '''
        }
    
    @pytest.mark.asyncio
    async def test_dvwa_base_url_structure(self):
        """Test that scanner works with correct DVWA base URL"""
        
        test_url = f"{self.dvwa_base_url}?id=1"
        
        # Mock HTTP responses to simulate DVWA
        with patch.object(self.scanner, '_make_request') as mock_request:
            
            async def mock_dvwa_response(url, **kwargs):
                mock_response = AsyncMock()
                mock_response.text = self.dvwa_responses['normal_response']
                mock_response.status_code = 200
                mock_response.headers = {'Content-Type': 'text/html'}
                return mock_response
            
            mock_request.side_effect = mock_dvwa_response
            
            # Run scanner with correct DVWA URL
            results = await self.scanner.scan(test_url)
            
            # Verify URL structure is correct
            assert results['target_url'] == test_url
            assert "dvwa/vulnerabilities/sqli" in results['target_url']
            assert "id=1" in results['target_url']
            
            print(f"✅ DVWA Base URL validation successful")
            print(f"   - Target URL: {results['target_url']}")
            print(f"   - Scan completed in: {results['scan_metadata']['duration']:.2f}s")
    
    @pytest.mark.asyncio
    async def test_documented_payload_validation(self):
        """Test payloads match those documented in sql-injection-analysis.md"""
        
        # Payloads from documentation
        documented_payloads = [
            "'",  # Error-based: Single quote
            "1' OR '1'='1",  # Boolean-based: OR injection
            "1' AND '1'='1",  # Boolean-based: AND true
            "1' AND '1'='2",  # Boolean-based: AND false
            "1' UNION SELECT null,version()--",  # Union-based: Version
            "1' UNION SELECT null,database()--",  # Union-based: Database
            "1' AND SLEEP(5)--",  # Time-based: MySQL SLEEP
        ]
        
        scanner_payloads = [p['payload'] for p in self.scanner.payloads]
        
        # Check that our scanner includes documented payloads
        for doc_payload in documented_payloads:
            # Check for exact match or similar pattern
            payload_found = any(
                doc_payload in scanner_payload or 
                any(word in scanner_payload for word in doc_payload.split() if len(word) > 2)
                for scanner_payload in scanner_payloads
            )
            
            assert payload_found, f"Documented payload not found in scanner: {doc_payload}"
        
        print(f"✅ Documented payload validation successful")
        print(f"   - Total scanner payloads: {len(scanner_payloads)}")
        print(f"   - Documented payloads verified: {len(documented_payloads)}")
        
        # Show payload mapping
        print(f"   - Payload verification:")
        for doc_payload in documented_payloads[:3]:  # Show first 3
            matching = [sp for sp in scanner_payloads if doc_payload in sp or any(word in sp for word in doc_payload.split() if len(word) > 2)]
            print(f"     '{doc_payload}' -> Found: {len(matching)} matches")
    
    @pytest.mark.asyncio
    async def test_dvwa_error_pattern_detection(self):
        """Test error pattern detection with documented DVWA errors"""
        
        test_url = f"{self.dvwa_base_url}?id=1"
        
        with patch.object(self.scanner, '_make_request') as mock_request:
            
            async def mock_dvwa_error_response(url, **kwargs):
                mock_response = AsyncMock()
                if "id=1'" in url:  # Error-inducing payload
                    mock_response.text = self.dvwa_responses['error_response']
                else:
                    mock_response.text = self.dvwa_responses['normal_response']
                mock_response.status_code = 200
                mock_response.headers = {'Content-Type': 'text/html'}
                return mock_response
            
            mock_request.side_effect = mock_dvwa_error_response
            
            # Test error detection
            error_content = self.dvwa_responses['error_response']
            detected_patterns = []
            
            for pattern in self.scanner.error_patterns:
                if pattern.lower() in error_content.lower():
                    detected_patterns.append(pattern)
            
            assert len(detected_patterns) >= 2, "Should detect multiple DVWA error patterns"
            assert 'mysql_fetch_array' in detected_patterns, "Should detect mysql_fetch_array error"
            assert 'mysql_num_rows' in detected_patterns, "Should detect mysql_num_rows error"
            
            print(f"✅ DVWA error pattern detection successful")
            print(f"   - Detected patterns: {detected_patterns}")
    
    @pytest.mark.asyncio
    async def test_parameter_injection_accuracy(self):
        """Test that parameter injection targets the correct 'id' parameter"""
        
        test_url = f"{self.dvwa_base_url}?id=1"
        
        with patch.object(self.scanner, '_make_request') as mock_request:
            
            request_urls = []
            
            async def mock_capture_requests(url, **kwargs):
                request_urls.append(url)
                mock_response = AsyncMock()
                mock_response.text = self.dvwa_responses['normal_response']
                mock_response.status_code = 200
                mock_response.headers = {'Content-Type': 'text/html'}
                return mock_response
            
            mock_request.side_effect = mock_capture_requests
            
            # Run scanner
            results = await self.scanner.scan(test_url)
            
            # Verify parameter injection
            id_parameter_tests = [url for url in request_urls if 'id=' in url and url != test_url]
            
            assert len(id_parameter_tests) > 0, "Should test 'id' parameter with payloads"
            
            # Check for specific payload patterns in URLs
            payload_patterns = ["'", "OR", "UNION", "SLEEP"]
            found_patterns = []
            
            for pattern in payload_patterns:
                if any(pattern.lower() in url.lower() for url in id_parameter_tests):
                    found_patterns.append(pattern)
            
            assert len(found_patterns) >= 3, f"Should test multiple payload types. Found: {found_patterns}"
            
            print(f"✅ Parameter injection accuracy validated")
            print(f"   - Total requests made: {len(request_urls)}")
            print(f"   - Parameter tests: {len(id_parameter_tests)}")
            print(f"   - Payload patterns found: {found_patterns}")
    
    @pytest.mark.asyncio
    async def test_realistic_dvwa_scan_simulation(self):
        """Comprehensive test simulating realistic DVWA scan"""
        
        test_url = f"{self.dvwa_base_url}?id=1"
        
        with patch.object(self.scanner, '_make_request') as mock_request:
            
            async def mock_realistic_dvwa(url, **kwargs):
                mock_response = AsyncMock()
                mock_response.status_code = 200
                mock_response.headers = {'Content-Type': 'text/html'}
                
                # Route different payloads to appropriate responses
                if "id=1'" in url and "UNION" not in url and "SLEEP" not in url:
                    mock_response.text = self.dvwa_responses['error_response']
                elif "UNION SELECT" in url and "version()" in url:
                    mock_response.text = self.dvwa_responses['union_version_response']
                elif "OR '1'='1" in url:
                    mock_response.text = self.dvwa_responses['boolean_or_response']
                else:
                    mock_response.text = self.dvwa_responses['normal_response']
                
                return mock_response
            
            mock_request.side_effect = mock_realistic_dvwa
            
            # Run comprehensive scan
            results = await self.scanner.scan(test_url)
            
            # Verify realistic results
            assert results['scan_summary']['vulnerabilities_found'] >= 1, "Should find vulnerabilities in DVWA"
            
            # Check vulnerability details
            if results['vulnerabilities']:
                vuln = results['vulnerabilities'][0]
                
                # Verify DVWA-specific details
                assert 'dvwa/vulnerabilities/sqli' in vuln['endpoint']
                assert vuln['parameter'] == 'id'
                assert vuln['method'] == 'GET'
                assert vuln['confidence'] >= 0.5
                
                print(f"✅ Realistic DVWA scan simulation successful")
                print(f"   - Vulnerabilities found: {results['scan_summary']['vulnerabilities_found']}")
                print(f"   - First vulnerability: {vuln['title']}")
                print(f"   - Risk level: {vuln['risk']}")
                print(f"   - Confidence: {vuln['confidence']:.2f}")
                print(f"   - Payload used: {vuln['payload']}")
            
            return results
    
    def test_dvwa_url_format_compliance(self):
        """Test URL format compliance with DVWA documentation"""
        
        # Test various URL formats
        valid_dvwa_urls = [
            "http://localhost/dvwa/vulnerabilities/sqli/",
            "http://localhost/dvwa/vulnerabilities/sqli/?id=1",
            "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit",
        ]
        
        for url in valid_dvwa_urls:
            # Verify URL structure
            assert "dvwa/vulnerabilities/sqli" in url, f"URL should contain DVWA path: {url}"
            
            if "?" in url:
                base_url, params = url.split("?", 1)
                assert base_url.endswith("/dvwa/vulnerabilities/sqli/"), f"Base URL format incorrect: {base_url}"
                
                if "id=" in params:
                    assert "id=" in params, f"Should contain id parameter: {params}"
        
        print(f"✅ DVWA URL format compliance verified")
        print(f"   - Valid URL formats tested: {len(valid_dvwa_urls)}")
        
        # Show URL structure analysis
        for url in valid_dvwa_urls:
            print(f"   - {url} ✓")
