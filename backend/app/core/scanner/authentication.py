"""
Authentication Module for Vulnity Scanner
Based on DVWA analysis findings
"""

import requests
from typing import Optional, Dict, Any
import logging
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time

logger = logging.getLogger(__name__)


class AuthenticationManager:
    """
    Manages authentication for web vulnerability scanning
    Based on DVWA login analysis:
    - POST method to login.php
    - Parameters: username, password, Login
    - Session management with PHP cookies
    - Default credentials: admin/password
    """
    
    def __init__(self, base_url: str, timeout: int = 30):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.timeout = timeout
        self.authenticated = False
        self.login_url = None
        self.csrf_token = None
        
        # Set user agent
        self.session.headers.update({
            'User-Agent': 'Vulnity-Scanner/1.0 (Vulnerability Scanner)'
        })
        
    def detect_login_form(self) -> Optional[Dict[str, Any]]:
        """
        Detect login form based on DVWA analysis
        Returns form details if found
        """
        try:
            # Common login paths based on analysis
            login_paths = [
                '/login.php',
                '/login',
                '/admin/login',
                '/auth/login',
                '/'
            ]
            
            for path in login_paths:
                url = urljoin(self.base_url, path)
                logger.info(f"Checking for login form at: {url}")
                
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Look for login form
                    forms = soup.find_all('form')
                    for form in forms:
                        # Check for username/password fields
                        username_field = form.find('input', {'type': 'text'}) or \
                                       form.find('input', {'name': 'username'}) or \
                                       form.find('input', {'name': 'user'})
                        
                        password_field = form.find('input', {'type': 'password'}) or \
                                       form.find('input', {'name': 'password'})
                        
                        if username_field and password_field:
                            # Extract form details
                            action = form.get('action', '')
                            method = form.get('method', 'post').lower()
                            
                            # Handle relative URLs
                            if action:
                                form_url = urljoin(url, action)
                            else:
                                form_url = url
                            
                            # Extract CSRF token if present
                            csrf_token = None
                            csrf_field = form.find('input', {'type': 'hidden'})
                            if csrf_field:
                                csrf_token = csrf_field.get('value')
                            
                            form_details = {
                                'url': form_url,
                                'method': method,
                                'username_field': username_field.get('name', 'username'),
                                'password_field': password_field.get('name', 'password'),
                                'csrf_token': csrf_token,
                                'csrf_field': csrf_field.get('name') if csrf_field else None
                            }
                            
                            logger.info(f"Login form detected: {form_details}")
                            self.login_url = form_url
                            return form_details
            
            logger.warning("No login form detected")
            return None
            
        except Exception as e:
            logger.error(f"Error detecting login form: {str(e)}")
            return None
    
    def login_dvwa(self, username: str = "admin", password: str = "password") -> bool:
        """
        DVWA-specific login based on analysis findings
        """
        try:
            # DVWA login URL from analysis
            login_url = urljoin(self.base_url, '/login.php')
            
            # Get login page first (for session initialization)
            response = self.session.get(login_url, timeout=self.timeout)
            if response.status_code != 200:
                logger.error(f"Failed to access login page: {response.status_code}")
                return False
            
            # Prepare login data based on DVWA analysis
            login_data = {
                'username': username,
                'password': password,
                'Login': 'Login'  # Submit button name from analysis
            }
            
            # Submit login
            logger.info(f"Attempting DVWA login with credentials: {username}")
            response = self.session.post(login_url, data=login_data, timeout=self.timeout)
            
            # Check for successful login (redirect to index.php from analysis)
            if response.status_code == 302 or 'index.php' in response.url:
                logger.info("DVWA login successful - redirected to index.php")
                self.authenticated = True
                return True
            elif response.status_code == 200:
                # Check response content for success indicators
                if 'Welcome to Damn Vulnerable Web Application' in response.text or \
                   'Logout' in response.text:
                    logger.info("DVWA login successful - welcome message detected")
                    self.authenticated = True
                    return True
            
            logger.error("DVWA login failed - no success indicators found")
            return False
            
        except Exception as e:
            logger.error(f"DVWA login error: {str(e)}")
            return False
    
    def generic_login(self, username: str, password: str, 
                     form_details: Optional[Dict[str, Any]] = None) -> bool:
        """
        Generic login method for other applications
        """
        try:
            if not form_details:
                form_details = self.detect_login_form()
                if not form_details:
                    return False
            
            # Prepare login data
            login_data = {
                form_details['username_field']: username,
                form_details['password_field']: password
            }
            
            # Add CSRF token if present
            if form_details['csrf_token'] and form_details['csrf_field']:
                login_data[form_details['csrf_field']] = form_details['csrf_token']
            
            # Submit login
            logger.info(f"Attempting generic login to: {form_details['url']}")
            if form_details['method'] == 'post':
                response = self.session.post(form_details['url'], data=login_data, 
                                           timeout=self.timeout)
            else:
                response = self.session.get(form_details['url'], params=login_data, 
                                          timeout=self.timeout)
            
            # Check for successful login
            success_indicators = [
                'dashboard', 'welcome', 'logout', 'profile', 'admin panel'
            ]
            
            if any(indicator in response.text.lower() for indicator in success_indicators):
                logger.info("Generic login successful")
                self.authenticated = True
                return True
            
            logger.error("Generic login failed")
            return False
            
        except Exception as e:
            logger.error(f"Generic login error: {str(e)}")
            return False
    
    def is_authenticated(self) -> bool:
        """Check if currently authenticated"""
        return self.authenticated
    
    def logout(self) -> bool:
        """Logout from the application"""
        try:
            # Try common logout URLs
            logout_paths = ['/logout.php', '/logout', '/auth/logout']
            
            for path in logout_paths:
                url = urljoin(self.base_url, path)
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    logger.info("Logout successful")
                    self.authenticated = False
                    return True
            
            # Clear session anyway
            self.session.cookies.clear()
            self.authenticated = False
            return True
            
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return False
    
    def get_session(self) -> requests.Session:
        """Get the authenticated session"""
        return self.session
    
    def test_authentication(self, test_url: str = None) -> bool:
        """
        Test if authentication is still valid
        """
        try:
            if not test_url:
                test_url = urljoin(self.base_url, '/index.php')
            
            response = self.session.get(test_url, timeout=self.timeout)
            
            # Check for login redirect or login form
            if 'login' in response.url.lower() or \
               'login' in response.text.lower() and 'password' in response.text.lower():
                self.authenticated = False
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Authentication test error: {str(e)}")
            return False
