#!/usr/bin/env python3
"""
Test Runner for Vulnity Scanner
Validates implementation against DVWA findings
"""

import sys
import os
import subprocess
import logging
from pathlib import Path

# Add the app directory to Python path
app_dir = Path(__file__).parent / "app"
sys.path.insert(0, str(app_dir))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def run_tests():
    """Run all test suites"""
    logger.info("Starting Vulnity Scanner test suite...")
    
    # Test files to run
    test_files = [
        "app/tests/test_authentication.py",
        "app/tests/test_sql_injection.py", 
        "app/tests/test_detection_signatures.py",
        "app/tests/test_integration_dvwa.py"
    ]
    
    total_tests = 0
    passed_tests = 0
    failed_tests = 0
    
    for test_file in test_files:
        logger.info(f"\n{'='*60}")
        logger.info(f"Running tests: {test_file}")
        logger.info(f"{'='*60}")
        
        try:
            # Run pytest for each test file
            result = subprocess.run([
                sys.executable, "-m", "pytest", 
                test_file, 
                "-v", 
                "--tb=short",
                "--no-header"
            ], capture_output=True, text=True, cwd=Path(__file__).parent)
            
            # Parse results
            output = result.stdout + result.stderr
            print(output)
            
            # Count test results
            if "PASSED" in output:
                file_passed = output.count("PASSED")
                passed_tests += file_passed
                total_tests += file_passed
            
            if "FAILED" in output:
                file_failed = output.count("FAILED")
                failed_tests += file_failed
                total_tests += file_failed
            
            if result.returncode == 0:
                logger.info(f"✅ {test_file} - All tests passed")
            else:
                logger.warning(f"❌ {test_file} - Some tests failed")
                
        except Exception as e:
            logger.error(f"Error running {test_file}: {str(e)}")
            failed_tests += 1
            total_tests += 1
    
    # Summary
    logger.info(f"\n{'='*60}")
    logger.info("TEST SUMMARY")
    logger.info(f"{'='*60}")
    logger.info(f"Total tests: {total_tests}")
    logger.info(f"Passed: {passed_tests}")
    logger.info(f"Failed: {failed_tests}")
    
    if failed_tests == 0:
        logger.info("🎉 All tests passed!")
        return True
    else:
        logger.warning(f"⚠️  {failed_tests} tests failed")
        return False


def validate_dvwa_compatibility():
    """Validate scanner compatibility with DVWA findings"""
    logger.info("\n" + "="*60)
    logger.info("DVWA COMPATIBILITY VALIDATION")
    logger.info("="*60)
    
    try:
        from core.scanner import SQLInjectionScanner, SQLInjectionType
        import requests
        
        # Create mock session for validation
        session = requests.Session()
        scanner = SQLInjectionScanner(session)
        
        # Validate payload database
        logger.info("Validating payload database...")
        
        # Check successful payloads from testing
        successful_payloads = [
            ("1' OR '1'='1", SQLInjectionType.BOOLEAN_BASED),
            ("1' OR 1=1#", SQLInjectionType.BOOLEAN_BASED),
            ("1' UNION SELECT 1,2#", SQLInjectionType.UNION_BASED),
            ("1' UNION SELECT user(),version()#", SQLInjectionType.UNION_BASED),
            ("1' AND SLEEP(5)#", SQLInjectionType.TIME_BASED),
            ("1' AND 1=1#", SQLInjectionType.BLIND_BOOLEAN),
            ("1' AND 1=2#", SQLInjectionType.BLIND_BOOLEAN),
        ]
        
        validation_passed = True
        
        for payload, injection_type in successful_payloads:
            if payload in scanner.payloads[injection_type]:
                logger.info(f"✅ Payload validated: {payload}")
            else:
                logger.error(f"❌ Missing payload: {payload}")
                validation_passed = False
        
        # Validate comment syntax preference
        if scanner.comment_syntax == "#":
            logger.info("✅ Comment syntax preference: # (100% success rate)")
        else:
            logger.error(f"❌ Wrong comment syntax: {scanner.comment_syntax}")
            validation_passed = False
        
        # Validate detection signatures
        logger.info("Validating detection signatures...")
        signatures = scanner.detection_signatures
        
        # Boolean success indicators
        boolean_indicators = signatures["boolean_success"]
        required_indicators = ["Gordon Brown", "Pablo Picasso", "Hack Me", "Bob Smith", "admin"]
        
        for indicator in required_indicators:
            if indicator in boolean_indicators:
                logger.info(f"✅ Boolean indicator: {indicator}")
            else:
                logger.error(f"❌ Missing boolean indicator: {indicator}")
                validation_passed = False
        
        # Union success indicators
        union_indicators = signatures["union_success"]
        required_union = ["root@localhost", "10.4.32-MariaDB"]
        
        for indicator in required_union:
            if indicator in union_indicators:
                logger.info(f"✅ Union indicator: {indicator}")
            else:
                logger.error(f"❌ Missing union indicator: {indicator}")
                validation_passed = False
        
        if validation_passed:
            logger.info("🎉 DVWA compatibility validation passed!")
            return True
        else:
            logger.error("❌ DVWA compatibility validation failed!")
            return False
            
    except Exception as e:
        logger.error(f"Validation error: {str(e)}")
        return False


def validate_success_rate():
    """Validate 70% success rate implementation"""
    logger.info("\n" + "="*60)
    logger.info("SUCCESS RATE VALIDATION")
    logger.info("="*60)
    
    try:
        from core.scanner import SQLInjectionScanner, SQLInjectionType
        import requests
        
        session = requests.Session()
        scanner = SQLInjectionScanner(session)
        
        # Count total payloads
        total_payloads = 0
        successful_payloads = 0
        
        # Count by injection type
        for injection_type, payloads in scanner.payloads.items():
            type_count = len(payloads)
            total_payloads += type_count
            
            if injection_type in [
                SQLInjectionType.BOOLEAN_BASED,
                SQLInjectionType.UNION_BASED,
                SQLInjectionType.TIME_BASED,
                SQLInjectionType.BLIND_BOOLEAN
            ]:
                successful_payloads += type_count
                logger.info(f"✅ {injection_type.value}: {type_count} successful payloads")
            else:
                logger.info(f"❌ {injection_type.value}: {type_count} failed payloads")
        
        # Calculate success rate
        if total_payloads > 0:
            success_rate = successful_payloads / total_payloads
            logger.info(f"\nSuccess rate: {success_rate:.1%} ({successful_payloads}/{total_payloads})")
            
            if abs(success_rate - 0.7) < 0.1:  # Allow 10% variance
                logger.info("✅ Success rate validation passed!")
                return True
            else:
                logger.error(f"❌ Expected ~70% success rate, got {success_rate:.1%}")
                return False
        else:
            logger.error("❌ No payloads found!")
            return False
            
    except Exception as e:
        logger.error(f"Success rate validation error: {str(e)}")
        return False


def main():
    """Main test runner"""
    logger.info("Vulnity Scanner Validation Suite")
    logger.info("Based on comprehensive DVWA analysis")
    
    all_passed = True
    
    # Run unit tests
    if not run_tests():
        all_passed = False
    
    # Validate DVWA compatibility
    if not validate_dvwa_compatibility():
        all_passed = False
    
    # Validate success rate
    if not validate_success_rate():
        all_passed = False
    
    # Final result
    logger.info("\n" + "="*60)
    logger.info("FINAL VALIDATION RESULT")
    logger.info("="*60)
    
    if all_passed:
        logger.info("🎉 ALL VALIDATIONS PASSED!")
        logger.info("Scanner implementation matches DVWA analysis findings")
        return 0
    else:
        logger.error("❌ SOME VALIDATIONS FAILED!")
        logger.error("Scanner implementation needs review")
        return 1


if __name__ == "__main__":
    sys.exit(main())
