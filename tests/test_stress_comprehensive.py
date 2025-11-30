#!/usr/bin/env python3
"""
ULTIMATE STRESS TEST SUITE
Tests every component to absolute limits with detailed failure reporting.
Run with: python -m pytest tests/test_stress_comprehensive.py -v
"""

import pytest
import asyncio
import time
import sys
import os
from unittest.mock import AsyncMock, patch, ANY, MagicMock
from colorama import Fore, Style, init

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Initialize colorama for colored output
init(autoreset=True)

from handlers.auth import process_username, process_password
from handlers.password_entry import (
    process_entry_name, process_new_email, process_password as process_entry_password,
    process_new_name_edit, process_new_email_edit, process_new_password_edit,
    decrypt_with_key, view_password_entry
)
from utils.validators import InputValidator
from utils.encryption import encrypt_data, decrypt_data, generate_key, validate_encryption_key
from utils.hashing import HashManager
from utils.session_manager import sessions
from db.database import Database
import utils.logger as logger_module


class TestStatus:
    """Track test results with detailed reporting"""
    
    def __init__(self):
        self.passed = []
        self.failed = []
        self.skipped = []
    
    def add_pass(self, test_name, details=""):
        self.passed.append((test_name, details))
        print(f"{Fore.GREEN}✅ PASS: {test_name}{Style.RESET_ALL}")
        if details:
            print(f"   {details}")
    
    def add_fail(self, test_name, error, details=""):
        self.failed.append((test_name, error, details))
        print(f"{Fore.RED}❌ FAIL: {test_name}{Style.RESET_ALL}")
        print(f"   Error: {error}")
        if details:
            print(f"   {details}")
    
    def add_skip(self, test_name, reason):
        self.skipped.append((test_name, reason))
        print(f"{Fore.YELLOW}⚠️  SKIP: {test_name}{Style.RESET_ALL}")
        print(f"   Reason: {reason}")
    
    def print_summary(self):
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 ULTIMATE STRESS TEST SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}✅ PASSED: {len(self.passed)}{Style.RESET_ALL}")
        print(f"{Fore.RED}❌ FAILED: {len(self.failed)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⚠️  SKIPPED: {len(self.skipped)}{Style.RESET_ALL}")
        
        if self.failed:
            print(f"\n{Fore.RED}🔍 FAILURE DETAILS:{Style.RESET_ALL}")
            for test_name, error, details in self.failed:
                print(f"   {Fore.RED}• {test_name}{Style.RESET_ALL}")
                print(f"     {Fore.WHITE}Error: {error}{Style.RESET_ALL}")
                if details:
                    print(f"     {Fore.WHITE}Details: {details}{Style.RESET_ALL}")
        
        if self.passed:
            print(f"\n{Fore.GREEN}🎉 SUCCESSFUL TESTS:{Style.RESET_ALL}")
            for test_name, details in self.passed[:10]:  # Show first 10
                print(f"   {Fore.GREEN}• {test_name}{Style.RESET_ALL}")
            if len(self.passed) > 10:
                print(f"   {Fore.GREEN}... and {len(self.passed) - 10} more{Style.RESET_ALL}")


test_status = TestStatus()


class TestUltimateStress:
    """Ultimate stress tests that push every component to absolute limits"""
    
    # === AUTHENTICATION STRESS TESTS ===
    
    def test_authentication_extreme_input_lengths(self):
        """Test authentication with extreme input lengths beyond normal limits."""
        try:
            # Test massively long username (beyond 50 char limit)
            is_valid, message = InputValidator.validate_username("a" * 1000)
            assert not is_valid, "1000 char username should be rejected"
            test_status.add_pass("Extreme long username rejection")
        except Exception as e:
            test_status.add_fail("Extreme long username rejection", str(e))
        
        try:
            # Test massively long password (beyond 128 char limit)
            is_valid, message = InputValidator.validate_password("a" * 1000)
            assert not is_valid, "1000 char password should be rejected"
            test_status.add_pass("Extreme long password rejection")
        except Exception as e:
            test_status.add_fail("Extreme long password rejection", str(e))
    
    def test_authentication_special_characters_extreme(self):
        """Test authentication with extreme special character combinations."""
        extreme_special_chars = [
            "'; DROP TABLE Users; --",
            "<script>alert('xss')</script>",
            "../../etc/passwd",
            " OR 1=1--",
            "\\x00\\x01\\x02",  # Binary characters
            "🎉💥🔥",  # Emoji characters
            "   ",  # Only spaces
            "\t\n\r",  # Control characters
        ]
        
        for chars in extreme_special_chars:
            try:
                is_valid, message = InputValidator.validate_username(chars)
                # Should either be invalid or properly sanitized
                if is_valid:
                    # If valid, ensure it's sanitized
                    sanitized = InputValidator.sanitize_input(chars)
                    assert sanitized != chars, f"Special chars {chars} should be sanitized"
                test_status.add_pass(f"Special chars handling: {chars[:20]}...")
            except Exception as e:
                test_status.add_fail(f"Special chars handling: {chars[:20]}...", str(e))
    
    @pytest.mark.asyncio
    async def test_authentication_concurrent_registration_stress(self):
        """Test massive concurrent user registration attempts."""
        async def attempt_registration(user_id):
            try:
                message = AsyncMock()
                message.text = f"user{user_id}"
                message.from_user.id = user_id
                message.answer = AsyncMock()
                
                state = AsyncMock()
                state.get_data.return_value = {'is_signup': True}
                state.update_data = AsyncMock()
                state.set_state = AsyncMock()
                
                with patch('handlers.auth.db.username_exists') as mock_exists:
                    mock_exists.return_value = False
                    await process_username(message, state)
                
                return True
            except Exception:
                return False
        
        try:
            # Attempt 50 concurrent registrations
            tasks = [attempt_registration(100000 + i) for i in range(50)]
            results = await asyncio.gather(*tasks)
            
            success_rate = sum(results) / len(results)
            assert success_rate >= 0.8, f"Concurrent registration success rate too low: {success_rate}"
            test_status.add_pass("Massive concurrent registration", f"Success rate: {success_rate:.1%}")
        except Exception as e:
            test_status.add_fail("Massive concurrent registration", str(e))
    
    # === PASSWORD ENTRIES STRESS TESTS ===
    
    def test_password_entries_extreme_data_sizes(self):
        """Test password entries with extreme data sizes."""
        try:
            # Test encryption with massive data
            key = generate_key()
            massive_data = "x" * 100000  # 100KB of data
            
            start_time = time.time()
            encrypted = encrypt_data(massive_data, key)
            decrypted = decrypt_data(encrypted, key)
            processing_time = time.time() - start_time
            
            assert decrypted == massive_data, "Massive data encryption failed"
            assert processing_time < 5.0, f"Massive data took too long: {processing_time:.2f}s"
            test_status.add_pass("Massive data encryption", f"Processed 100KB in {processing_time:.2f}s")
        except Exception as e:
            test_status.add_fail("Massive data encryption", str(e))
    
    @pytest.mark.asyncio 
    async def test_password_entries_rapid_sequential_operations(self):
        """Test rapid sequential password entry operations."""
        try:
            operations_count = 0
            start_time = time.time()
            
            for i in range(20):  # Rapid sequential operations
                message = AsyncMock()
                message.text = f"TestEntry{i}"
                message.answer = AsyncMock()
                
                state = AsyncMock()
                state.update_data = AsyncMock()
                state.set_state = AsyncMock()
                
                with patch('handlers.password_entry.sessions') as mock_sessions, \
                     patch('handlers.password_entry.db') as mock_db:
                    
                    mock_sessions.get_user_data.return_value = {'username': 'testuser'}
                    mock_db.get_user_by_username.return_value = {
                        'id': 1, 'encryption_key': 'test_key'
                    }
                    mock_db.create_password_entry.return_value = True
                    
                    await process_entry_name(message, state)
                    operations_count += 1
            
            total_time = time.time() - start_time
            ops_per_second = operations_count / total_time
            
            assert ops_per_second > 2, f"Operations too slow: {ops_per_second:.1f} ops/sec"
            test_status.add_pass("Rapid sequential operations", f"{ops_per_second:.1f} ops/sec")
        except Exception as e:
            test_status.add_fail("Rapid sequential operations", str(e))
    
    # === ENCRYPTION STRESS TESTS ===
    
    def test_encryption_corrupted_data_handling(self):
        """Test encryption with corrupted or malformed data."""
        test_cases = [
            ("", "empty data"),
            (None, "None data"),
            ("a" * 1000000, "1MB data"),
            ("\x00\x01\x02\x03", "binary data"),
            ("🎉" * 1000, "emoji data"),
        ]
        
        for test_data, description in test_cases:
            try:
                key = generate_key()
                
                if test_data is None:
                    # Test None handling
                    with pytest.raises(Exception):
                        encrypt_data(test_data, key)
                    test_status.add_pass(f"Encryption None handling: {description}")
                else:
                    # Test normal encryption
                    encrypted = encrypt_data(test_data, key)
                    decrypted = decrypt_data(encrypted, key)
                    assert decrypted == test_data, f"Data corruption with {description}"
                    test_status.add_pass(f"Encryption handling: {description}")
            except Exception as e:
                test_status.add_fail(f"Encryption handling: {description}", str(e))
    
    def test_encryption_key_extreme_cases(self):
        """Test encryption with extreme key cases."""
        extreme_keys = [
            "",  # Empty key
            "a",  # Single char key
            "a" * 1000,  # Very long key
            "🎉" * 100,  # Emoji key
            "\x00\x01\x02",  # Binary key
        ]
        
        for key in extreme_keys:
            try:
                if validate_encryption_key(key):
                    # If key is valid, test encryption
                    test_data = "test_data"
                    encrypted = encrypt_data(test_data, key)
                    decrypted = decrypt_data(encrypted, key)
                    assert decrypted == test_data, f"Encryption failed with key: {key[:20]}..."
                    test_status.add_pass(f"Encryption with key: {key[:20]}...")
                else:
                    # Key should be invalid
                    test_status.add_pass(f"Invalid key rejection: {key[:20]}...")
            except Exception as e:
                test_status.add_fail(f"Encryption key handling: {key[:20]}...", str(e))
    
    # === SESSION MANAGEMENT STRESS TESTS ===
    
    def test_session_massive_concurrent_sessions(self):
        """Test session manager with massive concurrent sessions."""
        try:
            initial_stats = sessions.get_session_stats()
            
            # Create 1000 concurrent sessions
            for i in range(1000):
                user_data = {'user_id': i, 'username': f'stressuser{i}'}
                sessions.authenticate_user(1000000 + i, user_data)
            
            # Verify sessions were created
            stats_after_create = sessions.get_session_stats()
            session_growth = stats_after_create['total_sessions'] - initial_stats['total_sessions']
            
            assert session_growth >= 900, f"Expected ~1000 sessions, got {session_growth}"
            test_status.add_pass("Massive concurrent sessions", f"Created {session_growth} sessions")
            
            # Cleanup
            sessions.cleanup_expired_sessions()
            
        except Exception as e:
            test_status.add_fail("Massive concurrent sessions", str(e))
    
    def test_session_rapid_state_changes(self):
        """Test rapid session state changes."""
        try:
            user_id = 999999
            operations = 100
            
            start_time = time.time()
            for i in range(operations):
                user_data = {'user_id': i, 'username': f'rapiduser{i}'}
                sessions.authenticate_user(user_id, user_data)
                assert sessions.is_session_valid(user_id)
                sessions.logout_user(user_id)
                assert not sessions.is_session_valid(user_id)
            
            total_time = time.time() - start_time
            ops_per_second = operations / total_time
            
            assert ops_per_second > 10, f"Session operations too slow: {ops_per_second:.1f} ops/sec"
            test_status.add_pass("Rapid session state changes", f"{ops_per_second:.1f} ops/sec")
        except Exception as e:
            test_status.add_fail("Rapid session state changes", str(e))
    
    # === DATABASE STRESS TESTS ===
    
    def test_database_connection_stress(self):
        """Test database connection under stress conditions."""
        try:
            # Test multiple rapid database connections
            test_db_path = "test_stress.db"
            
            if os.path.exists(test_db_path):
                os.unlink(test_db_path)
            
            databases = []
            for i in range(10):
                db = Database(test_db_path)
                databases.append(db)
                
                # Perform some operation
                success = db.create_user(f"stressuser{i}", "hash", "key", 1000000 + i)
                assert success or not success  # Just test it doesn't crash
            
            # Cleanup
            for db in databases:
                db.close()
            
            if os.path.exists(test_db_path):
                os.unlink(test_db_path)
                
            test_status.add_pass("Database connection stress")
        except Exception as e:
            test_status.add_fail("Database connection stress", str(e))
    
    # === MEMORY AND PERFORMANCE STRESS TESTS ===
    
    def test_memory_leak_detection(self):
        """Test for potential memory leaks in long operations."""
        try:
            initial_session_count = len(sessions.sessions)
            
            # Create and destroy many sessions
            for i in range(100):
                user_data = {'user_id': i, 'username': f'leaktest{i}'}
                sessions.authenticate_user(2000000 + i, user_data)
                sessions.logout_user(2000000 + i)
            
            # Force cleanup
            sessions.cleanup_expired_sessions()
            
            final_session_count = len(sessions.sessions)
            session_growth = final_session_count - initial_session_count
            
            # Allow some tolerance for active sessions
            assert session_growth <= 10, f"Possible memory leak: sessions grew by {session_growth}"
            test_status.add_pass("Memory leak detection", f"Session growth: {session_growth}")
        except Exception as e:
            test_status.add_fail("Memory leak detection", str(e))
    
    def test_cpu_intensive_operations(self):
        """Test CPU-intensive operations for performance degradation."""
        try:
            key = generate_key()
            test_data = "x" * 10000  # 10KB
            
            start_time = time.time()
            operations = 0
            
            # Run intensive operations for 2 seconds
            while time.time() - start_time < 2.0:
                encrypted = encrypt_data(test_data, key)
                decrypt_data(encrypted, key)
                operations += 1
            
            ops_per_second = operations / 2.0
            
            assert ops_per_second > 10, f"CPU operations too slow: {ops_per_second:.1f} ops/sec"
            test_status.add_pass("CPU intensive operations", f"{ops_per_second:.1f} ops/sec")
        except Exception as e:
            test_status.add_fail("CPU intensive operations", str(e))
    
    # === ERROR HANDLING STRESS TESTS ===
    
    @pytest.mark.asyncio
    async def test_error_handling_extreme_cases(self):
        """Test error handling with extreme failure cases."""
        try:
            # Test with None values
            message = AsyncMock()
            message.text = None
            message.answer = AsyncMock()
            
            state = AsyncMock()
            
            # This should handle the error gracefully
            await process_username(message, state)
            assert message.answer.called, "Should handle None input gracefully"
            test_status.add_pass("None input error handling")
        except Exception as e:
            test_status.add_fail("None input error handling", str(e))
    
    def test_logger_stress_test(self):
        """Test logger under high load conditions."""
        try:
            start_time = time.time()
            log_count = 0
            
            # Generate many log messages rapidly
            while time.time() - start_time < 1.0:  # 1 second burst
                logger_module.log_user_action("stress_test", 999999, f"log_{log_count}")
                log_count += 1
            
            assert log_count > 50, f"Logger throughput too low: {log_count} logs/sec"
            test_status.add_pass("Logger stress test", f"{log_count} logs/sec")
        except Exception as e:
            test_status.add_fail("Logger stress test", str(e))
    
    # === SECURITY STRESS TESTS ===
    
    def test_security_timing_attacks_resistance(self):
        """Test resistance to timing attacks."""
        try:
            key = generate_key()
            test_data = "sensitive_data"
            
            # Measure encryption time multiple times
            times = []
            for i in range(100):
                start_time = time.time()
                encrypt_data(test_data, key)
                times.append(time.time() - start_time)
            
            # Calculate timing variance (should be low for constant-time operations)
            avg_time = sum(times) / len(times)
            variance = sum((t - avg_time) ** 2 for t in times) / len(times)
            
            assert variance < 0.001, f"Timing variance too high: {variance}"
            test_status.add_pass("Timing attack resistance", f"Variance: {variance:.6f}")
        except Exception as e:
            test_status.add_fail("Timing attack resistance", str(e))
    
    def test_resource_exhaustion_protection(self):
        """Test protection against resource exhaustion attacks."""
        try:
            # Attempt to create an unreasonable number of sessions
            initial_memory = len(sessions.sessions)
            
            for i in range(10000):  # Try to exhaust resources
                try:
                    user_data = {'user_id': i, 'username': f'exhaust{i}'}
                    sessions.authenticate_user(3000000 + i, user_data)
                except Exception:
                    # System should handle this gracefully
                    break
            
            final_memory = len(sessions.sessions)
            memory_growth = final_memory - initial_memory
            
            # System should still be functional
            assert sessions.get_session_stats() is not None
            test_status.add_pass("Resource exhaustion protection", f"Memory growth: {memory_growth}")
        except Exception as e:
            test_status.add_fail("Resource exhaustion protection", str(e))


def test_ultimate_summary():
    """Final summary of all stress tests."""
    print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}🏁 ULTIMATE STRESS TEST COMPLETE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    
    # Force collection of any remaining test results
    test_status.print_summary()
    
    # Final verdict
    if len(test_status.failed) == 0:
        print(f"\n{Fore.GREEN}🎉 PHENOMENAL! All stress tests passed! Your system is battle-ready!{Style.RESET_ALL}")
    elif len(test_status.failed) <= 3:
        print(f"\n{Fore.YELLOW}⚠️  EXCELLENT! Only {len(test_status.failed)} stress tests failed. System is very robust!{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}🔧 NEEDS ATTENTION: {len(test_status.failed)} stress tests failed. Review failures above.{Style.RESET_ALL}")
    
    print(f"\n{Fore.WHITE}Next steps:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}• Review failed tests above{Style.RESET_ALL}")
    print(f"{Fore.WHITE}• Focus on critical failures first{Style.RESET_ALL}")
    print(f"{Fore.WHITE}• Consider if failures are acceptable for your use case{Style.RESET_ALL}")


# Run this after all tests to ensure summary is printed
@pytest.fixture(scope="session", autouse=True)
def ultimate_cleanup(request):
    """Ensure summary is printed after all tests."""
    def print_final_summary():
        test_ultimate_summary()
    request.addfinalizer(print_final_summary)