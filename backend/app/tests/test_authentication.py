"""
Test Suite for Authentication Module
Based on DVWA login analysis
"""

import pytest
import requests
from unittest.mock import Mock, patch
import sys
import os

# Add the parent directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner.authentication import AuthenticationManager


class TestAuthenticationManager:
    """Test cases for DVWA authentication based on analysis findings"""
    
    @pytest.fixture
    def auth_manager(self):
        """Create AuthenticationManager instance for testing"""
        return AuthenticationManager("http://localhost/dvwa")
    
    @pytest.fixture
    def mock_session(self):
        """Mock requests session"""
        return Mock(spec=requests.Session)
    
    def test_init(self, auth_manager):
        """Test AuthenticationManager initialization"""
        assert auth_manager.base_url == "http://localhost/dvwa"
        assert auth_manager.timeout == 30
        assert not auth_manager.authenticated
        assert auth_manager.session is not None
        assert "Vulnity-Scanner" in auth_manager.session.headers['User-Agent']
    
    @patch('requests.Session.get')
    def test_detect_login_form_dvwa(self, mock_get, auth_manager):
        """Test login form detection for DVWA"""
        # Mock DVWA login page response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '''
        <html>
        <body>
            <form action="login.php" method="post">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <input type="submit" name="Login" value="Login" />
            </form>
        </body>
        </html>
        '''
        mock_get.return_value = mock_response
        
        form_details = auth_manager.detect_login_form()
        
        assert form_details is not None
        assert form_details['username_field'] == 'username'
        assert form_details['password_field'] == 'password'
        assert form_details['method'] == 'post'
        assert 'login.php' in form_details['url']
    
    @patch('requests.Session.get')
    def test_detect_login_form_not_found(self, mock_get, auth_manager):
        """Test login form detection when no form is found"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '<html><body><h1>No login form here</h1></body></html>'
        mock_get.return_value = mock_response
        
        form_details = auth_manager.detect_login_form()
        assert form_details is None
    
    @patch('requests.Session.post')
    @patch('requests.Session.get')
    def test_login_dvwa_success(self, mock_get, mock_post, auth_manager):
        """Test successful DVWA login based on analysis"""
        # Mock login page response
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get.return_value = mock_get_response
        
        # Mock successful login response (redirect to index.php)
        mock_post_response = Mock()
        mock_post_response.status_code = 302
        mock_post_response.url = "http://localhost/dvwa/index.php"
        mock_post.return_value = mock_post_response
        
        result = auth_manager.login_dvwa("admin", "password")
        
        assert result is True
        assert auth_manager.authenticated is True
        
        # Verify correct login data was sent
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[1]['data']['username'] == 'admin'
        assert call_args[1]['data']['password'] == 'password'
        assert call_args[1]['data']['Login'] == 'Login'
    
    @patch('requests.Session.post')
    @patch('requests.Session.get')
    def test_login_dvwa_success_welcome_message(self, mock_get, mock_post, auth_manager):
        """Test DVWA login success detection via welcome message"""
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get.return_value = mock_get_response
        
        # Mock response with welcome message
        mock_post_response = Mock()
        mock_post_response.status_code = 200
        mock_post_response.url = "http://localhost/dvwa/login.php"
        mock_post_response.text = "Welcome to Damn Vulnerable Web Application"
        mock_post.return_value = mock_post_response
        
        result = auth_manager.login_dvwa("admin", "password")
        
        assert result is True
        assert auth_manager.authenticated is True
    
    @patch('requests.Session.post')
    @patch('requests.Session.get')
    def test_login_dvwa_failure(self, mock_get, mock_post, auth_manager):
        """Test failed DVWA login"""
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get.return_value = mock_get_response
        
        # Mock failed login response
        mock_post_response = Mock()
        mock_post_response.status_code = 200
        mock_post_response.url = "http://localhost/dvwa/login.php"
        mock_post_response.text = "Login failed"
        mock_post.return_value = mock_post_response
        
        result = auth_manager.login_dvwa("wrong", "credentials")
        
        assert result is False
        assert auth_manager.authenticated is False
    
    @patch('requests.Session.get')
    def test_login_dvwa_page_not_accessible(self, mock_get, auth_manager):
        """Test DVWA login when login page is not accessible"""
        mock_get.side_effect = requests.exceptions.RequestException("Connection error")
        
        result = auth_manager.login_dvwa("admin", "password")
        
        assert result is False
        assert auth_manager.authenticated is False
    
    def test_is_authenticated(self, auth_manager):
        """Test authentication status check"""
        assert not auth_manager.is_authenticated()
        
        auth_manager.authenticated = True
        assert auth_manager.is_authenticated()
    
    @patch('requests.Session.get')
    def test_logout(self, mock_get, auth_manager):
        """Test logout functionality"""
        auth_manager.authenticated = True
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        result = auth_manager.logout()
        
        assert result is True
        assert not auth_manager.authenticated
    
    def test_get_session(self, auth_manager):
        """Test getting the session object"""
        session = auth_manager.get_session()
        assert isinstance(session, requests.Session)
        assert session is auth_manager.session
    
    @patch('requests.Session.get')
    def test_test_authentication_valid(self, mock_get, auth_manager):
        """Test authentication validation when still valid"""
        auth_manager.authenticated = True
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.url = "http://localhost/dvwa/index.php"
        mock_response.text = "Dashboard content"
        mock_get.return_value = mock_response
        
        result = auth_manager.test_authentication()
        assert result is True
    
    @patch('requests.Session.get')
    def test_test_authentication_invalid(self, mock_get, auth_manager):
        """Test authentication validation when session expired"""
        auth_manager.authenticated = True
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.url = "http://localhost/dvwa/login.php"
        mock_response.text = "Please login"
        mock_get.return_value = mock_response
        
        result = auth_manager.test_authentication()
        assert result is False
        assert not auth_manager.authenticated
    
    @patch('requests.Session.post')
    @patch('requests.Session.get')
    def test_generic_login_success(self, mock_get, mock_post, auth_manager):
        """Test generic login functionality"""
        # Mock form detection
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.text = '''
        <form action="/login" method="post">
            <input type="text" name="user" />
            <input type="password" name="pass" />
        </form>
        '''
        mock_get.return_value = mock_get_response
        
        # Mock successful login
        mock_post_response = Mock()
        mock_post_response.status_code = 200
        mock_post_response.text = "Welcome to dashboard"
        mock_post.return_value = mock_post_response
        
        result = auth_manager.generic_login("testuser", "testpass")
        
        assert result is True
        assert auth_manager.authenticated is True
    
    @patch('requests.Session.get')
    def test_generic_login_no_form(self, mock_get, auth_manager):
        """Test generic login when no form is detected"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>No form here</body></html>"
        mock_get.return_value = mock_response
        
        result = auth_manager.generic_login("user", "pass")
        assert result is False


if __name__ == "__main__":
    pytest.main([__file__])
