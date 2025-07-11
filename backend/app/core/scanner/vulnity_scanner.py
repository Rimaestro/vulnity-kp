"""
Vulnity Web Vulnerability Scanner
Main scanner module integrating all components
Based on comprehensive DVWA analysis and testing results
"""

import logging
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
import json

from .authentication import AuthenticationManager
from .sql_injection import SQLInjectionScanner, SQLInjectionResult
from .detection_signatures import SQLInjectionSignatures

logger = logging.getLogger(__name__)


class VulnityScanner:
    """
    Main vulnerability scanner class
    Integrates authentication, SQL injection detection, and reporting
    Based on 70% success rate findings from DVWA testing
    """
    
    def __init__(self, target_url: str, timeout: int = 30):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.scan_results = {}
        self.scan_start_time = None
        self.scan_end_time = None
        
        # Initialize components
        self.auth_manager = AuthenticationManager(target_url, timeout)
        self.sql_scanner = None  # Will be initialized after authentication
        self.signatures = SQLInjectionSignatures()
        
        # Scanner configuration based on DVWA findings
        self.config = {
            "max_payloads_per_type": 10,
            "enable_time_based": True,
            "time_based_delay": 5,  # Based on SLEEP(5) testing
            "comment_syntax_preference": "#",  # 100% success rate with hash
            "confidence_threshold": 0.6,
            "enable_error_analysis": True,
            "max_scan_time": 300,  # 5 minutes max
        }
        
        logger.info(f"Vulnity Scanner initialized for target: {target_url}")
    
    def authenticate(self, username: str = None, password: str = None, 
                    auto_detect: bool = True) -> bool:
        """
        Authenticate with the target application
        """
        try:
            logger.info("Starting authentication process...")
            
            # Try DVWA-specific authentication first
            if auto_detect and self._is_dvwa_target():
                logger.info("DVWA target detected, using DVWA authentication")
                success = self.auth_manager.login_dvwa(
                    username or "admin", 
                    password or "password"
                )
            else:
                # Try generic authentication
                logger.info("Using generic authentication")
                success = self.auth_manager.generic_login(
                    username or "admin",
                    password or "password"
                )
            
            if success:
                # Initialize SQL scanner with authenticated session
                self.sql_scanner = SQLInjectionScanner(
                    self.auth_manager.get_session(), 
                    self.timeout
                )
                logger.info("Authentication successful, scanner ready")
                return True
            else:
                logger.warning("Authentication failed")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return False
    
    def _is_dvwa_target(self) -> bool:
        """Check if target appears to be DVWA"""
        dvwa_indicators = [
            "dvwa",
            "damn vulnerable web application",
            "/vulnerabilities/",
        ]
        
        target_lower = self.target_url.lower()
        return any(indicator in target_lower for indicator in dvwa_indicators)
    
    def scan_sql_injection(self, target_urls: List[str] = None, 
                          parameters: List[str] = None) -> Dict[str, Any]:
        """
        Perform SQL injection scanning
        """
        if not self.sql_scanner:
            logger.error("Scanner not initialized. Please authenticate first.")
            return {"error": "Scanner not initialized"}
        
        try:
            logger.info("Starting SQL injection scan...")
            scan_start = time.time()
            
            # Default to DVWA SQL injection URL if no URLs provided
            if not target_urls:
                if self._is_dvwa_target():
                    target_urls = [f"{self.target_url}/vulnerabilities/sqli/"]
                else:
                    target_urls = [self.target_url]
            
            results = {}
            
            for url in target_urls:
                logger.info(f"Scanning URL: {url}")
                
                # Auto-detect parameters if not provided
                if not parameters:
                    url_results = self.sql_scanner.scan_url(url)
                else:
                    url_results = {}
                    for param in parameters:
                        param_results = self.sql_scanner.scan_parameter(url, param)
                        if param_results:
                            url_results[param] = param_results
                
                if url_results:
                    results[url] = url_results
                    logger.info(f"Found {sum(len(vulns) for vulns in url_results.values())} vulnerabilities in {url}")
                else:
                    logger.info(f"No vulnerabilities found in {url}")
            
            scan_time = time.time() - scan_start
            logger.info(f"SQL injection scan completed in {scan_time:.2f} seconds")
            
            return {
                "scan_type": "sql_injection",
                "scan_time": scan_time,
                "results": results,
                "summary": self._generate_scan_summary(results)
            }
            
        except Exception as e:
            logger.error(f"SQL injection scan error: {str(e)}")
            return {"error": str(e)}
    
    def _generate_scan_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate scan summary statistics"""
        total_urls = len(results)
        total_parameters = sum(len(url_results) for url_results in results.values())
        total_vulnerabilities = sum(
            len(param_vulns) 
            for url_results in results.values() 
            for param_vulns in url_results.values()
        )
        
        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        injection_types = {}
        
        for url_results in results.values():
            for param_vulns in url_results.values():
                for vuln in param_vulns:
                    severity_counts[vuln.severity.value] += 1
                    injection_type = vuln.injection_type.value
                    injection_types[injection_type] = injection_types.get(injection_type, 0) + 1
        
        return {
            "total_urls_scanned": total_urls,
            "total_parameters_tested": total_parameters,
            "total_vulnerabilities_found": total_vulnerabilities,
            "severity_breakdown": severity_counts,
            "injection_types_found": injection_types,
            "vulnerable_urls": len([url for url, results in results.items() if results])
        }
    
    def perform_full_scan(self, username: str = None, password: str = None,
                         target_urls: List[str] = None) -> Dict[str, Any]:
        """
        Perform complete vulnerability scan
        """
        try:
            self.scan_start_time = time.time()
            logger.info("Starting full vulnerability scan...")
            
            # Step 1: Authentication
            auth_success = self.authenticate(username, password)
            if not auth_success:
                return {
                    "error": "Authentication failed",
                    "scan_completed": False,
                    "timestamp": time.time()
                }
            
            # Step 2: SQL Injection Scan
            sql_results = self.scan_sql_injection(target_urls)
            
            # Step 3: Generate comprehensive report
            self.scan_end_time = time.time()
            total_scan_time = self.scan_end_time - self.scan_start_time
            
            full_report = {
                "scan_info": {
                    "target_url": self.target_url,
                    "scan_start_time": self.scan_start_time,
                    "scan_end_time": self.scan_end_time,
                    "total_scan_time": total_scan_time,
                    "scanner_version": "1.0.0",
                    "scan_completed": True
                },
                "authentication": {
                    "status": "success",
                    "method": "dvwa" if self._is_dvwa_target() else "generic"
                },
                "sql_injection": sql_results,
                "overall_summary": self._generate_overall_summary(sql_results)
            }
            
            self.scan_results = full_report
            logger.info(f"Full scan completed in {total_scan_time:.2f} seconds")
            
            return full_report
            
        except Exception as e:
            logger.error(f"Full scan error: {str(e)}")
            return {
                "error": str(e),
                "scan_completed": False,
                "timestamp": time.time()
            }
    
    def _generate_overall_summary(self, sql_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall scan summary"""
        if "error" in sql_results:
            return {"status": "error", "message": sql_results["error"]}
        
        sql_summary = sql_results.get("summary", {})
        
        return {
            "scan_status": "completed",
            "vulnerabilities_found": sql_summary.get("total_vulnerabilities_found", 0),
            "critical_issues": sql_summary.get("severity_breakdown", {}).get("critical", 0),
            "high_issues": sql_summary.get("severity_breakdown", {}).get("high", 0),
            "medium_issues": sql_summary.get("severity_breakdown", {}).get("medium", 0),
            "low_issues": sql_summary.get("severity_breakdown", {}).get("low", 0),
            "risk_level": self._calculate_risk_level(sql_summary.get("severity_breakdown", {})),
            "recommendations": self._generate_recommendations(sql_results)
        }
    
    def _calculate_risk_level(self, severity_breakdown: Dict[str, int]) -> str:
        """Calculate overall risk level"""
        if severity_breakdown.get("critical", 0) > 0:
            return "CRITICAL"
        elif severity_breakdown.get("high", 0) > 0:
            return "HIGH"
        elif severity_breakdown.get("medium", 0) > 0:
            return "MEDIUM"
        elif severity_breakdown.get("low", 0) > 0:
            return "LOW"
        else:
            return "NONE"
    
    def _generate_recommendations(self, sql_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if "results" in sql_results and sql_results["results"]:
            recommendations.extend([
                "Implement parameterized queries/prepared statements for all database interactions",
                "Use input validation and sanitization on all user inputs",
                "Apply principle of least privilege for database accounts",
                "Enable Web Application Firewall (WAF) with SQL injection detection",
                "Conduct regular security code reviews and penetration testing",
                "Implement proper error handling to prevent information disclosure",
                "Use database query logging and monitoring for suspicious activities"
            ])
            
            # Add specific recommendations based on findings
            summary = sql_results.get("summary", {})
            if summary.get("injection_types_found", {}).get("union_based", 0) > 0:
                recommendations.append("Critical: Database credentials exposed - change database passwords immediately")
            
            if summary.get("injection_types_found", {}).get("time_based", 0) > 0:
                recommendations.append("Disable or restrict database functions like SLEEP() in application context")
        
        return recommendations
    
    def export_report(self, format: str = "json", filename: str = None) -> str:
        """Export scan results to file"""
        if not self.scan_results:
            raise ValueError("No scan results available. Run a scan first.")
        
        if not filename:
            timestamp = int(time.time())
            filename = f"vulnity_scan_report_{timestamp}.{format}"
        
        try:
            if format.lower() == "json":
                with open(filename, 'w') as f:
                    json.dump(self.scan_results, f, indent=2, default=str)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            logger.info(f"Report exported to: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Report export error: {str(e)}")
            raise
    
    def get_scan_results(self) -> Dict[str, Any]:
        """Get the latest scan results"""
        return self.scan_results
    
    def cleanup(self):
        """Cleanup scanner resources"""
        try:
            if self.auth_manager:
                self.auth_manager.logout()
            logger.info("Scanner cleanup completed")
        except Exception as e:
            logger.error(f"Cleanup error: {str(e)}")


# Convenience function for quick scanning
def quick_scan(target_url: str, username: str = None, password: str = None) -> Dict[str, Any]:
    """
    Perform a quick vulnerability scan
    """
    scanner = VulnityScanner(target_url)
    try:
        results = scanner.perform_full_scan(username, password)
        return results
    finally:
        scanner.cleanup()


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python vulnity_scanner.py <target_url> [username] [password]")
        sys.exit(1)
    
    target = sys.argv[1]
    user = sys.argv[2] if len(sys.argv) > 2 else None
    pwd = sys.argv[3] if len(sys.argv) > 3 else None
    
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Run scan
    results = quick_scan(target, user, pwd)
    print(json.dumps(results, indent=2, default=str))
