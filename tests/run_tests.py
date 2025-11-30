#!/usr/bin/env python3
"""
Comprehensive Test Runner for Password Manager Bot
Run all tests with: python tests/run_tests.py
"""

import os
import sys
import time
import pytest
import subprocess
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def print_header(text):
    """Print formatted header"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{text}")
    print(f"{'='*60}{Style.RESET_ALL}")

def print_success(text):
    """Print success message"""
    print(f"{Fore.GREEN}✅ {text}{Style.RESET_ALL}")

def print_error(text):
    """Print error message"""
    print(f"{Fore.RED}❌ {text}{Style.RESET_ALL}")

def print_warning(text):
    """Print warning message"""
    print(f"{Fore.YELLOW}⚠️  {text}{Style.RESET_ALL}")

def run_test_module(module_name, test_file):
    """Run specific test module and return detailed results"""
    print_header(f"RUNNING {module_name} TESTS")
    
    if os.path.exists(f"tests/{test_file}"):
        start_time = time.time()
        try:
            # Run with detailed output
            result = subprocess.run(
                [sys.executable, "-m", "pytest", f"tests/{test_file}", "-v", "--tb=short"],
                capture_output=True, text=True, timeout=120
            )
            elapsed = time.time() - start_time
            
            if result.returncode == 0:
                # Count passed tests from output
                passed_count = len([line for line in result.stdout.split('\n') if 'PASSED' in line])
                print_success(f"{test_file}: {passed_count} tests PASSED ({elapsed:.2f}s)")
                return passed_count, 0, elapsed, result.stdout
            else:
                # Count failed tests
                failed_lines = [line for line in result.stdout.split('\n') if 'FAILED' in line or 'ERROR' in line]
                failed_count = len(failed_lines)
                print_error(f"{test_file}: {failed_count} tests FAILED ({elapsed:.2f}s)")
                
                # Show first error for debugging
                if failed_lines:
                    print_warning(f"   First failure: {failed_lines[0].strip()}")
                return 0, failed_count, elapsed, result.stdout
                
        except subprocess.TimeoutExpired:
            print_error(f"{test_file}: TIMEOUT (120s)")
            return 0, 1, 120, ""
        except Exception as e:
            print_error(f"{test_file}: ERROR - {str(e)}")
            return 0, 1, 0, ""
    else:
        print_warning(f"{test_file}: NOT FOUND")
        return 0, 0, 0, ""

def main():
    """Main test runner function"""
    print_header("🚀 PASSWORD MANAGER BOT - COMPREHENSIVE TEST SUITE")
    
    # Test modules configuration
    test_modules = {
        "AUTHENTICATION": "test_authentication.py",
        "PASSWORD ENTRIES": "test_password_entries.py", 
        "SECURITY": "test_security.py",
        "PERFORMANCE": "test_performance.py",
        "INTEGRATION": "test_integration.py"
    }
    
    total_passed = 0
    total_failed = 0
    module_results = []
    
    # Run all test modules
    for module_name, test_file in test_modules.items():
        passed, failed, duration, output = run_test_module(module_name, test_file)
        total_passed += passed
        total_failed += failed
        module_results.append((module_name, passed, failed, duration))
    
    # Print summary
    print_header("📊 TEST SUMMARY")
    
    for module_name, passed, failed, duration in module_results:
        total = passed + failed
        if total > 0:
            status = f"{Fore.GREEN}PASS" if failed == 0 else f"{Fore.RED}FAIL"
            print(f"{module_name:<20} {passed:>2}/{total:<2} {status}{Style.RESET_ALL} {duration:>6.2f}s")
    
    total_tests = total_passed + total_failed
    print(f"\n{'TOTAL':<20} {total_passed:>2}/{total_tests:<2} ", end="")
    
    if total_failed == 0 and total_tests > 0:
        print_success(f"ALL TESTS PASSED ({total_passed} tests)")
        print(f"\n{Fore.GREEN}🎉 SUCCESS: Your bot is ready for production!{Style.RESET_ALL}")
        return 0
    elif total_tests == 0:
        print_error("NO TESTS FOUND")
        print(f"\n{Fore.RED}❌ No tests were discovered. Check test file paths.{Style.RESET_ALL}")
        return 1
    else:
        print_error(f"{total_failed} TEST(S) FAILED")
        print(f"\n{Fore.YELLOW}⚠️  Some tests need attention. Run individual tests for details:{Style.RESET_ALL}")
        print("  python -m pytest tests/test_authentication.py -v")
        print("  python -m pytest tests/test_security.py -v")
        print("  python -m pytest tests/test_password_entries.py -v")
        return 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Tests interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Test runner failed: {str(e)}")
        sys.exit(1)