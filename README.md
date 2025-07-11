# Vulnity - Web Vulnerability Scanner

Vulnity adalah scanner kerentanan web dengan pendekatan plugin yang terinspirasi dari w3af. Dibangun menggunakan Python modern dengan FastAPI untuk backend dan dukungan asynchronous untuk pemindaian yang cepat dan efisien.

## Fitur

- **Plugin-based architecture**: Memudahkan penambahan tipe pemindaian baru
- **Asynchronous scanning**: Menggunakan asyncio untuk pemindaian paralel yang efisien
- **REST API**: API yang lengkap untuk integrasi dengan tools lain
- **Web Interface**: Interface web modern dengan React dan TypeScript
- **Web crawler**: Menemukan URL dalam aplikasi web untuk dipindai
- **Pemindaian kerentanan**:
  - SQL Injection (Error-based, Blind, Time-based)
  - Cross-site Scripting (XSS)
  - Directory Traversal dan Local File Inclusion
  - Dan lainnya (dapat diperluas dengan plugin)

## Persyaratan

- Python 3.8+
- Node.js 16+ (untuk web interface)
- FastAPI
- aiohttp
- BeautifulSoup4
- Pydantic
- Uvicorn
- tldextract

## Instalasi

1. Clone repository ini:
```bash
git clone https://github.com/username/vulnity-kp.git
cd vulnity-kp
```

2. Setup Backend:
```bash
# Buat virtual environment dan aktifkan
python -m venv venv
source venv/bin/activate  # Untuk Linux/Mac
venv\Scripts\activate  # Untuk Windows

# Install dependencies backend
pip install -r requirements.txt
```

3. Setup Frontend (Web Interface):
```bash
cd frontend
npm install
```

## Penggunaan

### Menjalankan Backend

```bash
cd backend
python main.py
```

Backend akan berjalan pada http://localhost:8000

### Menjalankan Web Interface

```bash
cd frontend
npm start
```

Web interface akan berjalan pada http://localhost:3000

### API Endpoints

- `GET /api/` - Endpoint root API
- `GET /api/plugins` - Daftar plugin yang tersedia
- `POST /api/scan/start` - Mulai pemindaian baru
- `GET /api/scan/{scan_id}/status` - Dapatkan status pemindaian
- `GET /api/scan/{scan_id}/results` - Dapatkan hasil pemindaian

### Contoh request untuk memulai pemindaian

```bash
curl -X POST "http://localhost:8000/api/scan/start" \
     -H "Content-Type: application/json" \
     -d '{
           "url": "http://example.com",
           "scan_types": ["SQLInjectionScanner", "XSSScanner", "DirectoryTraversalScanner"],
           "options": {
             "max_depth": 3,
             "threads": 10,
             "timeout": 30,
             "follow_redirects": true
           }
         }'
```

## Web Interface

Vulnity dilengkapi dengan web interface modern yang dibangun menggunakan:

- **React 18** dengan TypeScript
- **Bootstrap 5** untuk styling
- **React Router** untuk navigation
- **Axios** untuk API calls
- **Font Awesome** untuk icons

### Fitur Web Interface

- **Dashboard**: Statistik real-time dan form pemindaian
- **Riwayat Pemindaian**: Melihat semua pemindaian yang telah dilakukan
- **Manajemen Plugin**: Melihat plugin yang tersedia
- **Responsive Design**: Kompatibel dengan desktop dan mobile

### Akses Web Interface

1. Jalankan backend: `cd backend && python main.py`
2. Jalankan frontend: `cd frontend && npm start`
3. Buka browser dan akses http://localhost:3000

## Arsitektur

Vulnity dibangun dengan arsitektur plugin yang fleksibel:

- **Core**:
  - `BaseScanner`: Kelas dasar untuk semua plugin scanner
  - `PluginManager`: Mengelola dan menjalankan plugin
  - `Models`: Model data untuk scan request, hasil, dll.

- **Plugins**:
  - `SQLInjectionScanner`: Mendeteksi kerentanan SQL injection
  - `XSSScanner`: Mendeteksi kerentanan Cross-site Scripting
  - `DirectoryTraversalScanner`: Mendeteksi kerentanan Directory Traversal
  - `WebSpider`: Crawler untuk menemukan URL dalam aplikasi web

- **API**:
  - RESTful API untuk mengelola pemindaian

- **Web Interface**:
  - React frontend untuk user interface
  - TypeScript untuk type safety
  - Bootstrap untuk responsive design

## Pengembangan

### Menambahkan plugin baru

1. Buat file Python baru di direktori yang sesuai (`plugins/audit/`, `plugins/crawl/`, dll.)
2. Buat kelas yang mewarisi `BaseScanner`
3. Implementasikan metode `scan()` yang diperlukan
4. Plugin akan otomatis terdeteksi saat aplikasi dimulai

Contoh plugin sederhana:

```python
from core.base_scanner import BaseScanner
from core.models import Vulnerability

class MyNewScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.name = "MyNewScanner"
        self.description = "My custom vulnerability scanner"
        
    async def scan(self, target_url):
        # Implementasi pemindaian
        return []  # Return daftar kerentanan
```

### Menambahkan fitur web interface

1. Buat komponen React di `frontend/src/components/`
2. Tambahkan halaman baru di `frontend/src/pages/`
3. Update routing di `frontend/src/App.tsx`
4. Tambahkan API endpoint di backend jika diperlukan

## Penyesuaian Modul SQL Injection Scanner

Modul SQL Injection Scanner telah ditingkatkan dengan beberapa penyesuaian untuk meningkatkan akurasi dan kinerja:

### 1. Penanganan Cookie dan Sesi yang Lebih Baik
- Implementasi manajemen cookie dan sesi untuk pengujian aplikasi yang memerlukan autentikasi
- Dukungan untuk menyimpan dan memperbarui cookie sesi secara otomatis
- Metode `_setup_cookies()` dan `_update_session_cookies()` untuk mengelola cookie

### 2. Deteksi Time-based yang Lebih Akurat
- Pengukuran baseline response time yang adaptif untuk mengurangi false positive
- Verifikasi ganda untuk konfirmasi kerentanan time-based
- Penyesuaian delay secara dinamis berdasarkan karakteristik server target

### 3. Penanganan URL Terenkode yang Lebih Baik
- Fungsi `_encode_payload_for_url()` untuk encoding yang menjaga karakter SQL Injection
- Dukungan double encoding untuk bypass WAF
- Normalisasi URL dengan `_normalize_url()` untuk konsistensi pengujian

### 4. Validasi Respons yang Lebih Cerdas
- Analisis konten respons yang lebih mendalam dengan `_analyze_response_content()`
- Deteksi perubahan struktur HTML yang mengindikasikan SQL Injection
- Identifikasi kebocoran data dalam respons

### 5. Dukungan Format Respons Berbeda
- Deteksi format respons (HTML, JSON, XML) dengan `_parse_response_format()`
- Ekstraksi bukti yang spesifik untuk setiap format respons
- Fungsi khusus untuk menganalisis respons JSON dan XML

### 6. Penanganan Error yang Lebih Baik
- Implementasi `_safe_request()` untuk penanganan error yang lebih robust
- Penanganan timeout dan exception yang lebih baik
- Logging yang lebih informatif untuk troubleshooting

### 7. Optimasi Rate Limiting
- Rate limiting adaptif berdasarkan respons server
- Implementasi cooldown untuk mencegah overload server
- Paralelisasi request dengan `_parallel_requests()` untuk efisiensi

## Cara Penggunaan

1. Clone repositori
2. Setup environment
3. Jalankan backend dan frontend
4. Akses dashboard melalui browser

## Pengujian

Untuk menjalankan pengujian:

```
python test_sqli_functions.py
```

## Lisensi

Proyek ini dilisensikan di bawah MIT License. 

## Kontribusi

Kontribusi sangat diterima! Silakan kirim pull request atau buka issue untuk diskusi.

## Credits

Proyek ini terinspirasi oleh [w3af](https://github.com/andresriancho/w3af).

# vulnity-kp
Vulnity-KP: Platform keamanan web untuk mendeteksi dan menganalisis kerentanan pada aplikasi web. Fitur: pemindaian otomatis, deteksi SQLi/XSS, dashboard, plugin-based, React+FastAPI.
