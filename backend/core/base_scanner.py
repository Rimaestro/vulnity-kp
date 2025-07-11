import abc
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Union
import urllib.parse

import aiohttp
from aiohttp import ClientTimeout
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from bs4 import BeautifulSoup

from core.models import (
    Vulnerability, 
    HttpRequest, 
    HttpResponse, 
    HttpMethod, 
    ScanOptions,
    VulnerabilityType,
    VulnerabilitySeverity
)


class BaseScanner(abc.ABC):
    """
    Base abstract class for all vulnerability scanners.
    
    This class defines the common interface and functionality for all scanner plugins.
    Scanner plugins should inherit from this class and implement the `scan` method.
    """
    
    def __init__(self):
        self.name: str = self.__class__.__name__
        self.description: str = "Base scanner plugin"
        self.vulnerabilities: List[Vulnerability] = []
        self.logger = logging.getLogger(f"scanner.{self.name}")
        self.session: Optional[aiohttp.ClientSession] = None
        self.options: Dict[str, Any] = {}
        self.scanned_urls: Set[str] = set()
        self._active = False
    
    async def setup(self, options: ScanOptions) -> None:
        """Initialize the scanner with the given options."""
        self.options = options.dict()
        timeout = ClientTimeout(total=options.timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)
        self._active = True
        self.logger.info(f"Scanner {self.name} initialized with options: {options}")
    
    async def cleanup(self) -> None:
        """Clean up resources used by the scanner."""
        if self.session and not self.session.closed:
            await self.session.close()
        self._active = False
        self.logger.info(f"Scanner {self.name} cleaned up")
    
    def is_active(self) -> bool:
        """Return whether the scanner is active."""
        return self._active
    
    @abc.abstractmethod
    async def scan(self, target_url: str) -> List[Vulnerability]:
        """
        Scan the target URL for vulnerabilities.
        
        This method must be implemented by subclasses.
        
        Args:
            target_url: The URL to scan
            
        Returns:
            A list of detected vulnerabilities
        """
        pass
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)),
        reraise=True
    )
    async def send_request(
        self, 
        url: str, 
        method: str = "GET", 
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        data: Optional[Union[Dict[str, Any], str]] = None,
        params: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> tuple[HttpRequest, HttpResponse]:
        """
        Send an HTTP request to the target URL and return the request and response objects.
        
        Args:
            url: Target URL
            method: HTTP method to use
            headers: Optional HTTP headers
            cookies: Optional cookies
            data: Optional request body (dict for form data, string for raw body)
            params: Optional query parameters
            timeout: Optional timeout in seconds
            
        Returns:
            Tuple of (HttpRequest, HttpResponse)
        """
        if not self.session:
            raise RuntimeError("Scanner not initialized. Call setup() first.")
        
        http_method = HttpMethod(method)
        headers = headers or {}
        cookies = cookies or {}
        
        # Handle data formatting based on content type
        request_data = None
        body_for_request_obj = None
        if data is not None:
            if isinstance(data, dict):
                # Convert dict to form data
                request_data = data
                body_for_request_obj = data
            else:
                # Use raw string data
                request_data = data
                body_for_request_obj = data
        
        # Create request object
        request = HttpRequest(
            url=url,
            method=http_method,
            headers=headers,
            cookies=cookies,
            body=body_for_request_obj
        )
        
        # Set custom timeout for this request if specified
        req_timeout = timeout if timeout is not None else self.options.get("timeout", 30)
        
        start_time = datetime.now()
        
        # Send the request
        try:
            async with self.session.request(
                method=method,
                url=url,
                headers=headers,
                cookies=cookies,
                data=request_data,
                params=params,
                timeout=req_timeout
            ) as resp:
                elapsed = (datetime.now() - start_time).total_seconds() * 1000  # ms
                body = await resp.text()
                
                # Create response object
                response = HttpResponse(
                    status_code=resp.status,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    body=body,
                    time_ms=elapsed
                )
                
                return request, response
                
        except Exception as e:
            self.logger.error(f"Error sending request to {url}: {str(e)}")
            raise
    
    def add_vulnerability(
        self,
        name: str,
        description: str,
        vuln_type: VulnerabilityType,
        severity: VulnerabilitySeverity,
        request: HttpRequest,
        response: HttpResponse,
        evidence: str,
        payload: Optional[str] = None,
        cwe_id: Optional[int] = None,
        remediation: Optional[str] = None
    ) -> Vulnerability:
        """
        Add a vulnerability to the list of detected vulnerabilities.
        
        Args:
            name: Vulnerability name
            description: Vulnerability description
            vuln_type: Type of vulnerability
            severity: Severity level
            request: The HTTP request that triggered the vulnerability
            response: The HTTP response that confirmed the vulnerability
            evidence: Evidence supporting the vulnerability
            payload: Optional payload used to trigger the vulnerability
            cwe_id: Optional CWE ID
            remediation: Optional remediation suggestion
            
        Returns:
            The created vulnerability object
        """
        vuln = Vulnerability(
            name=name,
            description=description,
            type=vuln_type,
            severity=severity,
            request=request,
            response=response,
            evidence=evidence,
            payload=payload,
            cwe_id=cwe_id,
            remediation=remediation
        )
        
        self.vulnerabilities.append(vuln)
        self.logger.info(f"Added vulnerability: {name} ({severity}) on {request.url}")
        
        return vuln
    
    def get_vulnerabilities(self) -> List[Vulnerability]:
        """Return the list of detected vulnerabilities."""
        return self.vulnerabilities
    
    def clear_vulnerabilities(self) -> None:
        """Clear the list of detected vulnerabilities."""
        self.vulnerabilities = []
    
    @staticmethod
    def extract_forms(html: str, base_url: str) -> List[Dict[str, Any]]:
        """
        Extract forms from HTML.
        
        Args:
            html: HTML content
            base_url: Base URL for resolving relative URLs
            
        Returns:
            List of dictionaries containing form information
        """
        forms = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for form in soup.find_all('form'):
            form_action = form.get('action', '')
            
            # Handle relative URLs
            if form_action and not form_action.startswith(('http://', 'https://')):
                if form_action.startswith('/'):
                    # Absolute path relative to domain
                    parsed_url = urllib.parse.urlparse(base_url)
                    form_action = f"{parsed_url.scheme}://{parsed_url.netloc}{form_action}"
                else:
                    # Relative path
                    form_action = urllib.parse.urljoin(base_url, form_action)
            
            # Default to the current URL if action is empty
            if not form_action:
                form_action = base_url
            
            form_method = form.get('method', 'GET').upper()
            form_inputs = []
            
            # Extract all input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text').lower()
                input_name = input_tag.get('name', '')
                input_value = input_tag.get('value', '')
                
                # Skip submit buttons and image inputs
                if input_type in ['submit', 'image', 'reset', 'button']:
                    continue
                
                # Skip inputs without a name
                if not input_name:
                    continue
                
                form_inputs.append({
                    'name': input_name,
                    'value': input_value,
                    'type': input_type
                })
            
            forms.append({
                'action': form_action,
                'method': form_method,
                'inputs': form_inputs
            })
        
        return forms
    
    @staticmethod
    def extract_links(html: str, base_url: str) -> List[str]:
        """
        Extract links from HTML.
        
        Args:
            html: HTML content
            base_url: Base URL for resolving relative URLs
            
        Returns:
            List of absolute URLs
        """
        links = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            
            # Skip empty links, javascript, and anchors
            if not href or href.startswith(('javascript:', '#')):
                continue
            
            # Handle relative URLs
            if not href.startswith(('http://', 'https://')):
                href = urllib.parse.urljoin(base_url, href)
            
            links.append(href)
        
        return links 