import asyncio
import re
from typing import Dict, List, Set, Any, Optional, Tuple
import urllib.parse
import tldextract

from core.base_scanner import BaseScanner
from core.models import (
    HttpRequest, 
    HttpResponse, 
    ScanOptions
)


class WebSpider(BaseScanner):
    """
    Web Spider untuk menjelajahi aplikasi web dan menemukan URL.
    
    Spider ini menjelajah aplikasi web dengan:
    1. Mengikuti link dari halaman awal
    2. Mengekstrak form dan parameter
    3. Mengidentifikasi URL baru untuk dipindai
    4. Menghormati aturan robots.txt
    """
    
    def __init__(self):
        super().__init__()
        self.name = "WebSpider"
        self.description = "Menjelajahi aplikasi web untuk menemukan URL yang bisa dipindai"
        
        # Menyimpan URL yang ditemukan
        self.found_urls: Set[str] = set()
        
        # Menyimpan URL yang sudah dikunjungi
        self.visited_urls: Set[str] = set()
        
        # Menyimpan form yang ditemukan
        self.found_forms: List[Dict[str, Any]] = []
        
        # File, ekstensi, dan direktori yang diabaikan
        self.ignored_extensions = {
            # File statis
            'jpg', 'jpeg', 'png', 'gif', 'bmp', 'ico', 'svg', 'webp',
            'css', 'less', 'scss', 'sass',
            'js', 'map', 'json', 'xml', 'woff', 'woff2', 'ttf', 'eot',
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
            'zip', 'rar', 'tar', 'gz', '7z',
            'mp3', 'mp4', 'avi', 'mov', 'wmv', 'flv', 'ogg', 'webm',
            # File yang tidak berkaitan dengan web
            'exe', 'dll', 'bin', 'dat', 'dmg', 'iso',
            'jar', 'war', 'ear',
            'swf', 'torrent',
        }
        
        self.ignored_dirs = {
            # Direktori umum yang diabaikan
            '__MACOSX',
            '.git', '.svn', '.hg', '.bzr', '.idea', '.vscode',
            'node_modules', 'bower_components', 'vendor',
            'logs', 'log', 'temp', 'tmp',
            'cache', 'caches',
        }
        
        # Regex untuk mengekstrak URL dari HTML
        self.url_pattern = re.compile(r'(href|src|action|data|location)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
        self.js_url_pattern = re.compile(r'(url|location)\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE)
        self.css_url_pattern = re.compile(r'url\([\'"]?([^\'")]+)[\'"]?\)', re.IGNORECASE)
        
        # Menyimpan robot rules
        self.robots_txt_rules: Dict[str, List[str]] = {}
        self.robots_txt_checked = False
    
    async def scan(self, target_url: str) -> List[str]:
        """
        Jelajahi aplikasi web dimulai dari URL target.
        
        Args:
            target_url: URL awal untuk menjelajah
            
        Returns:
            Daftar URL yang ditemukan
        """
        self.logger.info(f"Mulai menjelajahi {target_url}")
        
        # Reset URL yang ditemukan dan dikunjungi
        self.found_urls = set()
        self.visited_urls = set()
        self.found_forms = []
        
        # Parse URL target untuk mendapatkan domain
        parsed_url = urllib.parse.urlparse(target_url)
        self.base_domain = parsed_url.netloc
        self.target_scheme = parsed_url.scheme
        self.base_url = f"{self.target_scheme}://{self.base_domain}"
        
        # Ekstrak domain utama untuk pembatasan crawling
        domain_info = tldextract.extract(self.base_domain)
        if domain_info.subdomain:
            self.main_domain = f"{domain_info.subdomain}.{domain_info.domain}.{domain_info.suffix}"
        else:
            self.main_domain = f"{domain_info.domain}.{domain_info.suffix}"
        
        # Periksa robots.txt
        await self._check_robots_txt()
        
        # Tambahkan URL target ke daftar yang akan dikunjungi
        self.found_urls.add(target_url)
        
        # Mulai dari URL target
        max_depth = self.options.get('max_depth', 3)
        max_urls = self.options.get('max_urls', 100)
        
        # Batasi jumlah URL yang dikunjungi
        urls_processed = 0
        
        # Menjelajah sampai kedalaman maksimum
        for depth in range(max_depth + 1):
            self.logger.info(f"Menjelajahi kedalaman {depth}/{max_depth}")
            
            # URL yang akan dikunjungi pada kedalaman ini
            urls_to_visit = list(self.found_urls - self.visited_urls)
            
            if not urls_to_visit:
                self.logger.info(f"Tidak ada lagi URL untuk dikunjungi pada kedalaman {depth}")
                break
            
            # Batasi jumlah URL per kedalaman
            if len(urls_to_visit) > max_urls - urls_processed:
                urls_to_visit = urls_to_visit[:max_urls - urls_processed]
                self.logger.info(f"Dibatasi {len(urls_to_visit)} URL untuk dikunjungi pada kedalaman {depth}")
            
            # Buat tugas untuk mengunjungi URL secara paralel
            tasks = []
            for url in urls_to_visit:
                if self._should_visit(url):
                    tasks.append(self._visit_url(url, depth))
            
            # Tunggu semua tugas selesai
            await asyncio.gather(*tasks)
            
            # Perbarui jumlah URL yang diproses
            urls_processed += len(urls_to_visit)
            if urls_processed >= max_urls:
                self.logger.info(f"Mencapai batas maksimum URL ({max_urls})")
                break
        
        self.logger.info(f"Selesai menjelajahi {target_url}, menemukan {len(self.found_urls)} URL dan {len(self.found_forms)} form")
        
        # Hapus URL yang diabaikan
        self.found_urls = {url for url in self.found_urls if self._should_visit(url)}
        
        return list(self.found_urls)
    
    async def _visit_url(self, url: str, depth: int) -> None:
        """
        Kunjungi URL dan ekstrak link dan form.
        
        Args:
            url: URL untuk dikunjungi
            depth: Kedalaman saat ini dalam penjelajahan
        """
        # Periksa jika URL sudah dikunjungi
        if url in self.visited_urls:
            return
        
        # Tandai URL sebagai sudah dikunjungi
        self.visited_urls.add(url)
        
        # Periksa jika URL seharusnya diabaikan berdasarkan robots.txt
        if not self._is_allowed_by_robots(url):
            self.logger.debug(f"Melewati URL {url} (dilarang oleh robots.txt)")
            return
        
        try:
            self.logger.debug(f"Mengunjungi {url}")
            request, response = await self.send_request(url)
            
            # Periksa jika respons adalah HTML
            content_type = response.headers.get('content-type', '')
            is_html = 'text/html' in content_type.lower() or 'application/xhtml+xml' in content_type.lower()
            
            if is_html and response.body:
                # Ekstrak link dari halaman
                new_urls = self._extract_urls(response.body, url)
                
                # Tambahkan URL baru ke daftar yang akan dikunjungi
                for new_url in new_urls:
                    if new_url not in self.found_urls and new_url not in self.visited_urls and self._should_visit(new_url):
                        self.found_urls.add(new_url)
                        self.logger.debug(f"Menemukan URL baru: {new_url}")
                
                # Ekstrak form dari halaman
                forms = self.extract_forms(response.body, url)
                for form in forms:
                    # Tambahkan URL form ke daftar yang akan dikunjungi
                    form_action = form.get('action', '')
                    if form_action and form_action not in self.found_urls and form_action not in self.visited_urls:
                        self.found_urls.add(form_action)
                        self.logger.debug(f"Menemukan URL form: {form_action}")
                    
                    # Tambahkan form ke daftar form yang ditemukan
                    self.found_forms.append(form)
                    self.logger.debug(f"Menemukan form: {form.get('action', '')}")
        
        except Exception as e:
            self.logger.error(f"Error mengunjungi {url}: {str(e)}")
    
    def _extract_urls(self, html: str, base_url: str) -> List[str]:
        """
        Ekstrak URL dari konten HTML.
        
        Args:
            html: Konten HTML
            base_url: URL dasar untuk URL relatif
            
        Returns:
            Daftar URL absolut yang ditemukan
        """
        urls = set()
        
        # Ekstrak URL dari atribut HTML (href, src, action, dll.)
        for _, url in self.url_pattern.findall(html):
            abs_url = self._make_absolute_url(url.strip(), base_url)
            if abs_url:
                urls.add(abs_url)
        
        # Ekstrak URL dari JavaScript
        for _, url in self.js_url_pattern.findall(html):
            abs_url = self._make_absolute_url(url.strip(), base_url)
            if abs_url:
                urls.add(abs_url)
        
        # Ekstrak URL dari CSS
        for url, in self.css_url_pattern.findall(html):
            abs_url = self._make_absolute_url(url.strip(), base_url)
            if abs_url:
                urls.add(abs_url)
        
        return list(urls)
    
    def _make_absolute_url(self, url: str, base_url: str) -> Optional[str]:
        """
        Mengubah URL relatif menjadi absolut.
        
        Args:
            url: URL relatif atau absolut
            base_url: URL dasar untuk URL relatif
            
        Returns:
            URL absolut atau None jika invalid
        """
        # Lewati URL kosong, anchor, atau protokol khusus
        if not url or url.startswith(('#', 'javascript:', 'data:', 'mailto:', 'tel:', 'sms:', 'ftp:')):
            return None
        
        try:
            # Gabungkan URL relatif dengan URL dasar
            abs_url = urllib.parse.urljoin(base_url, url)
            
            # Hapus fragment
            abs_url = abs_url.split('#')[0]
            
            # Hapus trailing slash jika ada
            if abs_url.endswith('/'):
                abs_url = abs_url[:-1]
            
            # Pastikan URL memiliki skema
            parsed_url = urllib.parse.urlparse(abs_url)
            if not parsed_url.scheme:
                abs_url = f"{self.target_scheme}://{abs_url}"
            
            # Periksa jika URL memiliki domain yang sama
            if not self._is_same_site(abs_url):
                return None
            
            return abs_url
            
        except Exception as e:
            self.logger.error(f"Error membuat URL absolut untuk {url}: {str(e)}")
            return None
    
    def _is_same_site(self, url: str) -> bool:
        """
        Periksa jika URL berada di domain yang sama.
        
        Args:
            url: URL untuk diperiksa
            
        Returns:
            True jika URL berada di domain yang sama, False jika tidak
        """
        try:
            parsed_url = urllib.parse.urlparse(url)
            
            # Ekstrak domain dari URL
            domain_info = tldextract.extract(parsed_url.netloc)
            if domain_info.subdomain:
                url_domain = f"{domain_info.subdomain}.{domain_info.domain}.{domain_info.suffix}"
            else:
                url_domain = f"{domain_info.domain}.{domain_info.suffix}"
            
            # Periksa jika domain sama dengan target
            return url_domain == self.main_domain
            
        except Exception:
            return False
    
    def _should_visit(self, url: str) -> bool:
        """
        Periksa jika URL seharusnya dikunjungi berdasarkan aturan pengabaian.
        
        Args:
            url: URL untuk diperiksa
            
        Returns:
            True jika URL seharusnya dikunjungi, False jika tidak
        """
        try:
            # Periksa jika URL adalah None
            if url is None:
                return False
            
            # Periksa jika URL diizinkan oleh robots.txt
            if not self._is_allowed_by_robots(url):
                return False
            
            # Parse URL
            parsed_url = urllib.parse.urlparse(url)
            
            # Periksa domain
            if parsed_url.netloc and parsed_url.netloc != self.base_domain:
                return False
            
            # Periksa path
            path = parsed_url.path.lower()
            
            # Periksa ekstensi file
            if '.' in path:
                extension = path.split('.')[-1]
                if extension in self.ignored_extensions:
                    return False
            
            # Periksa direktori yang diabaikan
            path_parts = path.split('/')
            for part in path_parts:
                if part in self.ignored_dirs:
                    return False
            
            return True
            
        except Exception:
            return False
    
    async def _check_robots_txt(self) -> None:
        """Periksa file robots.txt dan ekstrak aturan yang relevan."""
        if self.robots_txt_checked:
            return
        
        robots_url = f"{self.base_url}/robots.txt"
        
        try:
            self.logger.debug(f"Memeriksa {robots_url}")
            request, response = await self.send_request(robots_url)
            
            # Periksa jika respons berhasil
            if response.status_code == 200 and response.body:
                self._parse_robots_txt(response.body)
            
        except Exception as e:
            self.logger.error(f"Error memeriksa robots.txt: {str(e)}")
        finally:
            self.robots_txt_checked = True
    
    def _parse_robots_txt(self, robots_txt: str) -> None:
        """
        Parse konten robots.txt dan ekstrak aturan.
        
        Args:
            robots_txt: Konten robots.txt
        """
        current_agent = "*"
        self.robots_txt_rules = {"*": []}
        
        lines = robots_txt.split('\n')
        for line in lines:
            line = line.strip()
            
            # Lewati komentar dan baris kosong
            if not line or line.startswith('#'):
                continue
            
            # Parse baris
            if ':' in line:
                directive, value = line.split(':', 1)
                directive = directive.lower().strip()
                value = value.strip()
                
                if directive == "user-agent":
                    current_agent = value
                    if current_agent not in self.robots_txt_rules:
                        self.robots_txt_rules[current_agent] = []
                
                elif directive == "disallow":
                    if value:
                        self.robots_txt_rules[current_agent].append(value)
        
        self.logger.debug(f"Parsed robots.txt rules: {self.robots_txt_rules}")
    
    def _is_allowed_by_robots(self, url: str) -> bool:
        """
        Periksa jika URL diizinkan oleh robots.txt.
        
        Args:
            url: URL untuk diperiksa
            
        Returns:
            True jika URL diizinkan, False jika dilarang
        """
        # Jika follow_robots dinonaktifkan dalam opsi, selalu izinkan
        if not self.options.get('follow_robots', True):
            return True
        
        # Jika robots.txt tidak diperiksa, izinkan
        if not self.robots_txt_checked or not self.robots_txt_rules:
            return True
        
        try:
            # Parse URL
            parsed_url = urllib.parse.urlparse(url)
            path = parsed_url.path
            
            # Periksa aturan untuk user-agent tertentu (kami menggunakan aturan umum *)
            for disallow in self.robots_txt_rules.get("*", []):
                if path.startswith(disallow):
                    return False
            
            return True
            
        except Exception:
            # Jika ada error, izinkan
            return True
