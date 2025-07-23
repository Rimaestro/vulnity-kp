"""
Base Scanner Service for vulnerability scanning
Following existing codebase patterns and DVWA analysis findings
"""

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse
import httpx

from app.config.logging import get_logger
from app.config.settings import settings


class BaseScanner(ABC):
    """
    Abstract base class for all vulnerability scanners
    Following existing codebase patterns and integrating with httpx AsyncClient
    """
    
    def __init__(self):
        self.logger = get_logger("scanner.base")
        self.session_timeout = getattr(settings, 'SCANNER_REQUEST_TIMEOUT', 30)
        self.max_concurrent_requests = getattr(settings, 'SCANNER_MAX_CONCURRENT_REQUESTS', 5)
        self.request_delay = getattr(settings, 'SCANNER_REQUEST_DELAY', 1.0)
        
        # Rate limiting
        self.semaphore = asyncio.Semaphore(self.max_concurrent_requests)
        self.last_request_time = 0
        
        # HTTP client configuration following httpx best practices
        self.client_config = {
            'timeout': httpx.Timeout(
                connect=10.0,
                read=self.session_timeout,
                write=10.0,
                pool=10.0
            ),
            'limits': httpx.Limits(
                max_keepalive_connections=10,
                max_connections=20
            ),
            'follow_redirects': False,  # Handle redirects manually for better control
            'verify': True,  # SSL verification
            'headers': {
                'User-Agent': 'Vulnity-KP Scanner/1.0 (Security Testing)',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
        }

        # Session management for authenticated scanning
        self.session_cookies = {}
        self.authenticated_domains = set()
    
    async def _get_http_client(self) -> httpx.AsyncClient:
        """
        Get configured HTTP client following httpx best practices
        """
        # Include session cookies if available
        client_config = self.client_config.copy()
        if self.session_cookies:
            client_config['cookies'] = self.session_cookies

        return httpx.AsyncClient(**client_config)
    
    async def _rate_limit(self):
        """
        Implement rate limiting to avoid overwhelming target servers
        Following existing security patterns
        """
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        
        if time_since_last_request < self.request_delay:
            sleep_time = self.request_delay - time_since_last_request
            await asyncio.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    async def _make_request(
        self, 
        url: str, 
        method: str = "GET", 
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None
    ) -> Optional[httpx.Response]:
        """
        Make HTTP request with rate limiting and error handling
        Following existing logging and error handling patterns
        """
        
        async with self.semaphore:
            await self._rate_limit()
            
            try:
                async with await self._get_http_client() as client:
                    # Merge custom headers with default headers
                    request_headers = self.client_config['headers'].copy()
                    if headers:
                        request_headers.update(headers)
                    
                    # Use custom timeout if provided
                    request_timeout = timeout or self.session_timeout
                    
                    self.logger.debug(f"Making {method} request to {url}")
                    
                    response = await client.request(
                        method=method,
                        url=url,
                        params=params,
                        data=data,
                        headers=request_headers,
                        timeout=request_timeout
                    )

                    # Handle redirects manually for better control
                    if response.status_code in [301, 302, 303, 307, 308]:
                        redirect_url = response.headers.get('location')
                        if redirect_url and 'login' in redirect_url.lower():
                            self.logger.warning(f"Redirected to login page: {redirect_url}")
                            # Try to authenticate if this is DVWA
                            if '/dvwa/' in url.lower():
                                auth_success = await self._authenticate_dvwa(url)
                                if auth_success:
                                    # Retry the original request with new session
                                    async with await self._get_http_client() as new_client:
                                        response = await new_client.request(
                                            method=method,
                                            url=url,
                                            params=params,
                                            data=data,
                                            headers=request_headers,
                                            timeout=request_timeout
                                        )

                    self.logger.debug(f"Response: {response.status_code} for {url}")
                    return response
                    
            except httpx.TimeoutException as e:
                self.logger.warning(f"Request timeout for {url}: {str(e)}")
                return None
            except httpx.RequestError as e:
                self.logger.warning(f"Request error for {url}: {str(e)}")
                return None
            except Exception as e:
                self.logger.error(f"Unexpected error for {url}: {str(e)}")
                return None
    
    async def _make_get_request(
        self, 
        url: str, 
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Optional[httpx.Response]:
        """Convenience method for GET requests"""
        return await self._make_request(url, "GET", params=params, headers=headers)
    
    async def _make_post_request(
        self, 
        url: str, 
        data: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Optional[httpx.Response]:
        """Convenience method for POST requests"""
        return await self._make_request(url, "POST", data=data, headers=headers)
    
    def _is_valid_url(self, url: str) -> bool:
        """
        Validate URL format and security constraints
        Following existing security validation patterns
        """
        try:
            from app.config.settings import get_settings

            parsed = urlparse(url)

            # Check basic URL structure
            if not parsed.scheme or not parsed.netloc:
                return False

            # Only allow HTTP and HTTPS
            if parsed.scheme.lower() not in ['http', 'https']:
                return False

            # Security checks - prevent SSRF (but allow localhost in development)
            settings = get_settings()

            # Allow localhost/internal networks in development environment
            if settings.ENVIRONMENT.lower() in ['development', 'dev', 'testing', 'test']:
                host = parsed.netloc.split(':')[0].lower()
                if host in ['localhost', '127.0.0.1'] and '/dvwa/' in url.lower():
                    self.logger.info(f"Allowing DVWA testing in development: {host}")
                    return True

            # Production security checks - prevent SSRF (following existing patterns)
            forbidden_hosts = [
                'localhost', '127.0.0.1', '0.0.0.0', '::1',
                '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                '172.30.', '172.31.', '192.168.'
            ]

            host = parsed.netloc.split(':')[0].lower()
            for forbidden in forbidden_hosts:
                if host.startswith(forbidden):
                    self.logger.warning(f"Blocked request to internal/private network: {host}")
                    return False

            return True

        except Exception as e:
            self.logger.warning(f"URL validation error: {str(e)}")
            return False
    
    def _extract_base_url(self, url: str) -> str:
        """Extract base URL from full URL"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _build_url(self, base_url: str, path: str) -> str:
        """Build full URL from base URL and path"""
        return urljoin(base_url, path)
    
    def _responses_similar(self, response1: httpx.Response, response2: httpx.Response) -> bool:
        """
        Compare two responses for similarity
        Used in boolean-based blind SQL injection detection (DVWA findings)
        """
        if not response1 or not response2:
            return False
        
        # Compare status codes
        if response1.status_code != response2.status_code:
            return False
        
        # Compare content length (with small tolerance)
        len1, len2 = len(response1.text), len(response2.text)
        if abs(len1 - len2) > 50:  # Allow small differences
            return False
        
        # Compare content similarity (basic check)
        # For more sophisticated comparison, could use difflib
        if response1.text == response2.text:
            return True
        
        # Check if responses are substantially similar
        similarity_ratio = len(set(response1.text.split()) & set(response2.text.split())) / max(
            len(set(response1.text.split())), 
            len(set(response2.text.split())), 
            1
        )
        
        return similarity_ratio > 0.8  # 80% similarity threshold
    
    def _extract_forms(self, response: httpx.Response) -> List[Dict[str, Any]]:
        """
        Extract forms from HTML response for parameter discovery
        Basic implementation - can be enhanced with BeautifulSoup if needed
        """
        forms = []
        
        try:
            # Basic form extraction using regex (can be improved)
            import re
            
            form_pattern = r'<form[^>]*>(.*?)</form>'
            input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
            
            form_matches = re.findall(form_pattern, response.text, re.DOTALL | re.IGNORECASE)
            
            for form_content in form_matches:
                inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
                if inputs:
                    forms.append({
                        'inputs': inputs,
                        'content': form_content
                    })
        
        except Exception as e:
            self.logger.warning(f"Error extracting forms: {str(e)}")
        
        return forms
    
    @abstractmethod
    async def scan(self, target_url: str, **kwargs) -> Dict[str, Any]:
        """
        Abstract method for performing vulnerability scan
        Must be implemented by concrete scanner classes
        
        Args:
            target_url: The URL to scan
            **kwargs: Additional scanner-specific parameters
            
        Returns:
            Dictionary containing scan results
        """
        pass
    
    async def _authenticate_dvwa(self, base_url: str) -> bool:
        """
        Authenticate with DVWA if needed
        """
        try:
            # Check if this is a DVWA URL
            if '/dvwa/' not in base_url.lower():
                return True

            domain = self._extract_base_url(base_url)

            # Check if already authenticated for this domain
            if domain in self.authenticated_domains:
                return True

            self.logger.info(f"Attempting DVWA authentication for {domain}")

            # Clear any existing cookies first
            self.session_cookies.clear()

            # Create a new client without existing cookies for authentication
            auth_client_config = self.client_config.copy()
            auth_client_config['follow_redirects'] = True  # Allow redirects during auth

            async with httpx.AsyncClient(**auth_client_config) as client:
                # Try to access DVWA login page
                login_url = f"{domain}/dvwa/login.php"

                # Get login page to extract CSRF token if needed
                login_response = await client.get(login_url)

                self.logger.debug(f"Login page response: {login_response.status_code}")
                self.logger.debug(f"Login page URL: {login_response.url}")

                if login_response.status_code != 200:
                    self.logger.warning(f"Could not access DVWA login page: {login_response.status_code}")
                    return False

                # Store any initial cookies from login page
                if login_response.cookies:
                    for cookie_name, cookie_value in login_response.cookies.items():
                        self.session_cookies[cookie_name] = cookie_value
                        self.logger.debug(f"Initial cookie: {cookie_name}={cookie_value}")

                # Check if we need to extract CSRF token
                csrf_token = None
                if 'user_token' in login_response.text:
                    import re
                    token_match = re.search(r'name=["\']user_token["\'] value=["\']([^"\']+)["\']', login_response.text)
                    if token_match:
                        csrf_token = token_match.group(1)
                        self.logger.debug(f"Found CSRF token: {csrf_token}")

                # Default DVWA credentials
                login_data = {
                    'username': 'admin',
                    'password': 'password',
                    'Login': 'Login'
                }

                # Add CSRF token if found
                if csrf_token:
                    login_data['user_token'] = csrf_token

                # Perform login with existing cookies
                self.logger.debug(f"Attempting login with data: {login_data}")
                auth_response = await client.post(
                    login_url,
                    data=login_data,
                    cookies=self.session_cookies
                )

                self.logger.debug(f"Login response: {auth_response.status_code}")
                self.logger.debug(f"Login response URL: {auth_response.url}")

                # Store all session cookies from login response
                if auth_response.cookies:
                    for cookie_name, cookie_value in auth_response.cookies.items():
                        self.session_cookies[cookie_name] = cookie_value
                        self.logger.debug(f"Login cookie: {cookie_name}={cookie_value}")

                # Test if authentication worked by trying to access a protected page
                test_url = f"{domain}/dvwa/vulnerabilities/sqli/"
                test_response = await client.get(test_url, cookies=self.session_cookies)

                self.logger.debug(f"Test response: {test_response.status_code}")
                self.logger.debug(f"Test response URL: {test_response.url}")
                self.logger.debug(f"Test response content preview: {test_response.text[:200]}")

                # If we can access the vulnerability page without redirect, auth succeeded
                if test_response.status_code == 200 and 'login' not in test_response.url.path.lower():
                    self.authenticated_domains.add(domain)
                    self.logger.info(f"Successfully authenticated with DVWA at {domain}")
                    self.logger.debug(f"Session cookies: {list(self.session_cookies.keys())}")
                    return True
                else:
                    self.logger.warning(f"DVWA authentication failed - still redirected to login")
                    self.logger.warning(f"Final URL: {test_response.url}")
                    return False

        except Exception as e:
            self.logger.error(f"Error during DVWA authentication: {str(e)}")
            return False

    async def cleanup(self):
        """
        Cleanup resources
        Following existing cleanup patterns
        """
        self.session_cookies.clear()
        self.authenticated_domains.clear()
        self.logger.info("Scanner cleanup completed")

    def __repr__(self):
        return f"<{self.__class__.__name__}(timeout={self.session_timeout})>"
