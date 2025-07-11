import asyncio
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Depends
from fastapi.responses import JSONResponse

from core.models import ScanRequest, ScanResult, ScanOptions, ScanStatus
from core.plugin_manager import plugin_manager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("api")

router = APIRouter()

# Store active scans
active_scans: Dict[str, ScanResult] = {}
scan_results: Dict[str, ScanResult] = {}


@router.get("/")
async def root():
    """Root endpoint untuk API"""
    return {"message": "Vulnity Web Vulnerability Scanner API", "version": "1.0.0"}


@router.get("/scan", response_model=List[Dict[str, Any]])
async def get_all_scans():
    """
    Dapatkan semua hasil pemindaian.
    """
    results = []
    for scan_id, scan in scan_results.items():
        vulnerabilities = []
        for vuln in scan.vulnerabilities:
            if isinstance(vuln, str):
                # Jika vulnerability berupa string, buat dict dengan informasi minimal
                vulnerabilities.append({
                    "type": "other",
                    "severity": "info",
                    "description": vuln,
                    "location": scan.target_url,
                    "evidence": vuln
                })
            else:
                # Jika vulnerability berupa objek Vulnerability
                vulnerabilities.append({
                    "type": vuln.type.value if hasattr(vuln.type, 'value') else str(vuln.type),
                    "severity": vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity),
                    "description": vuln.description,
                    "location": vuln.request.url,
                    "evidence": vuln.evidence[:200] + "..." if len(vuln.evidence) > 200 else vuln.evidence
                })
        
        results.append({
            "id": scan_id,
            "url": scan.target_url,
            "status": scan.status,
            "created_at": scan.start_time.isoformat(),
            "completed_at": scan.end_time.isoformat() if scan.end_time else None,
            "vulnerabilities": vulnerabilities
        })
    return results


@router.post("/scan/start", response_model=Dict[str, Any])
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Mulai pemindaian kerentanan pada URL target.
    """
    # Log request data
    logger.info(f"Received scan request: {request.dict()}")
    
    # Generate ID scan unik
    scan_id = str(uuid.uuid4())
    
    # Buat opsi pemindaian
    scan_options = ScanOptions(
        scan_types=request.scan_types,
        max_depth=request.options.max_depth,
        threads=request.options.threads,
        timeout=request.options.timeout,
        follow_redirects=request.options.follow_redirects,
        custom_parameters={"scan_id": scan_id}
    )
    
    # Log scan options
    logger.info(f"Created scan options: {scan_options.dict()}")
    
    # Buat objek hasil pemindaian awal
    result = ScanResult(
        scan_id=scan_id,
        target_url=request.url,
        start_time=datetime.now(),
        status=ScanStatus.PENDING,
        options=scan_options
    )
    
    # Simpan hasil awal
    active_scans[scan_id] = result
    scan_results[scan_id] = result
    
    # Jalankan pemindaian di background
    background_tasks.add_task(run_scan, scan_id, request.url, request.scan_types, scan_options)
    
    return {
        "scan_id": scan_id,
        "status": "pending",
        "message": "Pemindaian dimulai",
        "target": request.url,
        "scan_types": request.scan_types
    }


@router.get("/scan/{scan_id}/status", response_model=Dict[str, Any])
async def get_scan_status(scan_id: str):
    """
    Dapatkan status pemindaian.
    """
    # Periksa jika scan ID valid
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan ID tidak ditemukan")
    
    scan_result = scan_results[scan_id]
    
    return {
        "scan_id": scan_id,
        "status": scan_result.status,
        "target": scan_result.target_url,
        "start_time": scan_result.start_time.isoformat(),
        "end_time": scan_result.end_time.isoformat() if scan_result.end_time else None,
        "statistics": {
            "urls_crawled": scan_result.statistics.urls_crawled,
            "forms_tested": scan_result.statistics.forms_tested,
            "vulnerabilities_found": scan_result.statistics.vulnerabilities_found,
            "elapsed_time": scan_result.statistics.elapsed_time,
            "requests_sent": scan_result.statistics.requests_sent,
            "current_url": scan_result.statistics.current_url,
        }
    }


@router.get("/scan/{scan_id}/results", response_model=Dict[str, Any])
async def get_scan_results(scan_id: str):
    """
    Dapatkan hasil pemindaian.
    """
    # Periksa jika scan ID valid
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan ID tidak ditemukan")
    
    scan_result = scan_results[scan_id]
    
    # Jika pemindaian masih berjalan, kembalikan status
    if scan_result.status == ScanStatus.RUNNING or scan_result.status == ScanStatus.PENDING:
        return {
            "scan_id": scan_id,
            "status": scan_result.status,
            "message": "Pemindaian masih berjalan",
            "statistics": {
                "urls_crawled": scan_result.statistics.urls_crawled,
                "forms_tested": scan_result.statistics.forms_tested,
                "vulnerabilities_found": scan_result.statistics.vulnerabilities_found,
                "elapsed_time": scan_result.statistics.elapsed_time,
                "requests_sent": scan_result.statistics.requests_sent,
                "current_url": scan_result.statistics.current_url,
            }
        }
    
    # Format kerentanan untuk respons
    vulnerabilities = []
    for vuln in scan_result.vulnerabilities:
        if isinstance(vuln, str):
            # Jika vulnerability adalah string (dari WebSpider)
            vulnerabilities.append({
                "type": "info",
                "severity": "info",
                "description": vuln,
                "location": scan_result.target_url,
                "evidence": vuln,
                "discovered_at": scan_result.start_time.isoformat()
            })
        else:
            # Jika vulnerability adalah objek Vulnerability
            vulnerabilities.append({
                "type": vuln.type,
                "severity": vuln.severity,
                "description": vuln.description,
                "location": vuln.request.url if hasattr(vuln, 'request') else scan_result.target_url,
                "evidence": vuln.evidence[:200] + "..." if len(vuln.evidence) > 200 else vuln.evidence,
                "id": getattr(vuln, 'id', None),
                "name": getattr(vuln, 'name', None),
                "url": getattr(vuln, 'url', None),
                "method": getattr(vuln, 'method', None),
                "payload": getattr(vuln, 'payload', None),
                "cwe_id": getattr(vuln, 'cwe_id', None),
                "remediation": getattr(vuln, 'remediation', None),
                "discovered_at": getattr(vuln, 'discovered_at', scan_result.start_time).isoformat() if hasattr(vuln, 'discovered_at') else scan_result.start_time.isoformat()
            })
    
    return {
        "id": scan_id,
        "url": scan_result.target_url,
        "status": scan_result.status,
        "vulnerabilities": vulnerabilities,
        "created_at": scan_result.start_time.isoformat(),
        "completed_at": scan_result.end_time.isoformat() if scan_result.end_time else None,
        "statistics": {
            "urls_crawled": scan_result.statistics.urls_crawled,
            "forms_tested": scan_result.statistics.forms_tested,
            "vulnerabilities_found": scan_result.statistics.vulnerabilities_found,
            "elapsed_time": scan_result.statistics.elapsed_time,
            "requests_sent": scan_result.statistics.requests_sent,
        }
    }


@router.get("/plugins", response_model=List[str])
async def get_available_plugins():
    """
    Dapatkan daftar plugin yang tersedia.
    """
    # Temukan plugin yang tersedia
    plugin_manager.discover_plugins()
    
    return plugin_manager.get_plugin_names()


async def run_scan(scan_id: str, target_url: str, scan_types: List[str], options: ScanOptions):
    """
    Jalankan pemindaian di background.
    
    Args:
        scan_id: ID pemindaian
        target_url: URL target
        scan_types: Tipe pemindaian
        options: Opsi pemindaian
    """
    logger.info(f"Memulai pemindaian {scan_id} pada {target_url} dengan tipe {scan_types}")
    
    try:
        # Perbarui status
        scan_result = active_scans[scan_id]
        scan_result.status = ScanStatus.RUNNING
        
        # Temukan plugin yang tersedia
        plugin_manager.discover_plugins()
        
        # Jalankan web spider terlebih dahulu jika tersedia
        urls_to_scan = [target_url]
        if "WebSpider" in plugin_manager.get_plugin_names():
            try:
                # Buat instance web spider
                spider_options = ScanOptions(
                    scan_types=["WebSpider"],
                    max_depth=options.max_depth,
                    threads=options.threads,
                    timeout=options.timeout,
                    cookies=options.cookies,
                    headers=options.headers,
                    auth=options.auth,
                    follow_redirects=options.follow_redirects,
                    scan_ajax=options.scan_ajax,
                    custom_parameters=options.custom_parameters
                )
                
                spider = await plugin_manager.create_scanner("WebSpider", spider_options)
                spider_urls = await spider.scan(target_url)
                
                # Perbarui statistik
                scan_result.statistics.urls_crawled = len(spider_urls)
                
                # Tambahkan URL yang ditemukan untuk dipindai
                urls_to_scan.extend(spider_urls)
                urls_to_scan = list(set(urls_to_scan))  # Hapus duplikat
                
                # Cleanup web spider
                await spider.cleanup()
                
            except Exception as e:
                logger.error(f"Error menjalankan web spider: {str(e)}")
        
        # Filter scan types untuk hanya menggunakan yang tersedia
        available_plugins = plugin_manager.get_plugin_names()
        filtered_scan_types = [s for s in scan_types if s in available_plugins]
        
        # Jika tidak ada plugin yang valid, kembalikan error
        if not filtered_scan_types:
            scan_result.status = ScanStatus.FAILED
            scan_result.end_time = datetime.now()
            logger.error(f"Tidak ada plugin yang valid dalam {scan_types}. Tersedia: {available_plugins}")
            return
        
        # Jalankan pemindaian pada setiap URL yang ditemukan
        all_vulnerabilities = []
        
        for url in urls_to_scan[:options.max_depth * 10]:  # Batasi jumlah URL
            # Perbarui URL saat ini di statistik
            scan_result.statistics.current_url = url
            
            # Jalankan pemindaian pada URL ini
            result = await plugin_manager.run_scan(url, filtered_scan_types, options)
            
            # Tambahkan kerentanan yang ditemukan
            all_vulnerabilities.extend(result.vulnerabilities)
            
            # Perbarui statistik
            scan_result.statistics.requests_sent += sum(result.statistics.plugins_executed.values())
            scan_result.statistics.vulnerabilities_found = len(all_vulnerabilities)
        
        # Perbarui hasil pemindaian
        scan_result.vulnerabilities = all_vulnerabilities
        scan_result.end_time = datetime.now()
        scan_result.status = ScanStatus.COMPLETED
        scan_result.statistics.elapsed_time = (scan_result.end_time - scan_result.start_time).total_seconds()
        
        logger.info(f"Pemindaian {scan_id} selesai. Menemukan {len(all_vulnerabilities)} kerentanan.")
        
    except Exception as e:
        logger.error(f"Error menjalankan pemindaian {scan_id}: {str(e)}")
        
        # Perbarui status jika masih ada di active_scans
        if scan_id in active_scans:
            scan_result = active_scans[scan_id]
            scan_result.status = ScanStatus.FAILED
            scan_result.end_time = datetime.now()
    
    finally:
        # Cleanup resources
        await plugin_manager.cleanup_all()
        
        # Hapus dari active_scans
        if scan_id in active_scans:
            del active_scans[scan_id]
