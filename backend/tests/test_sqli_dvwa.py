import asyncio
import sys
import os
import re
import requests
from pathlib import Path
from http.cookies import SimpleCookie

# Add backend directory to Python path
current_dir = Path(__file__).resolve().parent.parent
sys.path.append(str(current_dir))

from plugins.audit.sqli import SQLInjectionScanner
from core.models import HttpRequest, HttpResponse, ScanOptions

def debug_dvwa_login():
    """Debug function to test DVWA login directly with requests"""
    print("\nDebug: Testing DVWA login with requests")
    
    login_url = "http://localhost/dvwa/login.php"
    
    try:
        # Create a session to maintain cookies
        session = requests.Session()
        
        # First request to get initial cookies and user_token
        print("\nGetting login page...")
        r = session.get(login_url)
        print("Response status:", r.status_code)
        print("Initial cookies:", dict(r.cookies))
        
        # Extract user_token using BeautifulSoup for more reliable parsing
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(r.text, 'html.parser')
        token_input = soup.find('input', {'name': 'user_token'})
        
        user_token = None
        if token_input and 'value' in token_input.attrs:
            user_token = token_input['value']
            print("\nFound user_token:", user_token)
        
        if not user_token:
            print("Could not find user_token")
            print("Response text (first 1000 chars):")
            print(r.text[:1000])
            return None
        
        # Login request with user_token
        login_data = {
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": user_token
        }
        
        print("\nSending login request with data:", login_data)
        
        # Login request
        r = session.post(login_url, data=login_data, allow_redirects=True)
        print("\nLogin response:")
        print("Status:", r.status_code)
        print("Cookies:", dict(r.cookies))
        print("Final URL:", r.url)
        
        # Get all cookies from session
        all_cookies = requests.utils.dict_from_cookiejar(session.cookies)
        print("\nAll session cookies:", all_cookies)
        
        # Make sure we have required cookies
        if 'PHPSESSID' not in all_cookies:
            print("Missing PHPSESSID cookie")
            return None
            
        # Set security level to low explicitly
        all_cookies['security'] = 'low'
        
        # Verify we can access a protected page
        print("\nVerifying access to protected page...")
        r = session.get("http://localhost/dvwa/vulnerabilities/sqli/")
        print("Status:", r.status_code)
        print("Final URL:", r.url)
        
        if "User ID" in r.text:
            print("\nLogin successful! Can access protected pages.")
            return all_cookies
        else:
            print("\nLogin verification failed - cannot access protected pages")
            print("Response text (first 500 chars):")
            print(r.text[:500])
            return None
            
    except Exception as e:
        print(f"\nError during login: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

async def test_dvwa_sqli():
    """
    Test SQL Injection scanner against DVWA
    """
    # Debug login first
    cookies = debug_dvwa_login()
    if not cookies:
        print("Debug login failed")
        return
        
    scanner = SQLInjectionScanner()
    
    # Scanner options with debug cookies
    options = ScanOptions(
        threads=5,
        timeout=10,
        max_depth=3,
        follow_redirects=True,
        headers={
            "User-Agent": "Vulnity-Scanner/1.0",
            "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())
        },
        cookies=cookies
    )
    
    try:
        # Initialize scanner
        await scanner.setup(options)
        
        # Target vulnerable pages with correct parameters
        target_urls = [
            "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit",
            "http://localhost/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit"
        ]
        
        # Debug: verify we can access the pages
        for url in target_urls:
            print(f"\nVerifying access to {url}")
            req, res = await scanner.send_request(
                url,
                headers={
                    "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())
                }
            )
            print("Request headers:", req.headers)
            print("Response status:", res.status_code)
            print("Response body (first 200 chars):", res.body[:200])
            if "User ID" not in res.body:
                print(f"Warning: Could not verify page content")
            else:
                print(f"Successfully accessed page")
        
        all_vulnerabilities = []
        
        for target_url in target_urls:
            print(f"\nScanning {target_url}")
            try:
                vulnerabilities = await scanner.scan(target_url)
                
                print("\nScan Results:")
                print("-" * 50)
                
                if not vulnerabilities:
                    print("No vulnerabilities found")
                else:
                    all_vulnerabilities.extend(vulnerabilities)
                    for vuln in vulnerabilities:
                        print(f"\nVulnerability Type: {vuln.type}")
                        print(f"Severity: {vuln.severity}")
                        print(f"URL: {vuln.url}")
                        if hasattr(vuln, 'parameter'):
                            print(f"Parameter: {vuln.parameter}")
                        if hasattr(vuln, 'payload'):
                            print(f"Payload: {vuln.payload}")
                        print(f"Evidence: {vuln.evidence}")
                        if hasattr(vuln, 'technical_detail'):
                            print("\nTechnical Details:")
                            for key, value in vuln.technical_detail.items():
                                print(f"{key}: {value}")
                        if hasattr(vuln, 'remediation'):
                            print("\nRemediation Steps:")
                            for step in vuln.remediation.get('steps', []):
                                print(f"- {step}")
                        print("-" * 50)
            except Exception as e:
                print(f"Error scanning {target_url}: {str(e)}")
                print("\n" + "-" * 50)
        
        # Print summary
        print("\nScan Summary:")
        print("-" * 50)
        print(f"Total URLs scanned: {len(target_urls)}")
        print(f"Total vulnerabilities found: {len(all_vulnerabilities)}")
        
        # Group vulnerabilities by type
        vuln_types = {}
        for vuln in all_vulnerabilities:
            if vuln.type not in vuln_types:
                vuln_types[vuln.type] = []
            vuln_types[vuln.type].append(vuln)
            
        print("\nVulnerabilities by type:")
        for vuln_type, vulns in vuln_types.items():
            print(f"{vuln_type}: {len(vulns)}")
                    
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        # Clean up scanner resources
        await scanner.cleanup()

if __name__ == "__main__":
    asyncio.run(test_dvwa_sqli()) 