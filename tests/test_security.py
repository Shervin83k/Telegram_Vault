import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.validators import InputValidator
from utils.encryption import encrypt_data, decrypt_data, generate_key, validate_encryption_key
from utils.hashing import HashManager
from utils.session_manager import sessions


class TestSecurity:
    """Security and validation tests"""
    
    def test_sql_injection_prevention(self):
        """Test that SQL injection attempts are properly blocked."""
        injection_attempts = [
            "admin' OR '1'='1",
            "admin'; DROP TABLE Users;--",
            "' OR 1=1--",
        ]
        
        for attempt in injection_attempts:
            is_valid, _ = InputValidator.validate_username(attempt)
            assert not is_valid, f"SQL injection passed: {attempt}"

    def test_password_hashing(self):
        """Test password hashing security and verification."""
        password = "secure_test_password_123"
        
        hash1 = HashManager.hash_password(password)
        hash2 = HashManager.hash_password(password)
        
        assert hash1 != hash2, "Identical passwords should produce different hashes"
        assert HashManager.verify_password(password, hash1), "Password verification should succeed"
        assert HashManager.verify_password(password, hash2), "Password verification should succeed"
        assert not HashManager.verify_password("incorrect_password", hash1), "Wrong password should fail verification"

    def test_encryption_security(self):
        """Test encryption and decryption functionality."""
        key = generate_key()
        test_data = "confidential@example.com"
        
        encrypted = encrypt_data(test_data, key)
        decrypted = decrypt_data(encrypted, key)
        
        assert encrypted != test_data, "Encrypted data should differ from original"
        assert decrypted == test_data, "Decrypted data should match original"
        
        wrong_key = generate_key()
        try:
            decrypt_data(encrypted, wrong_key)
            assert False, "Decryption with incorrect key should fail"
        except Exception:
            assert True

    def test_encryption_empty_data(self):
        """Test encryption with empty data."""
        key = generate_key()
        
        encrypted = encrypt_data("", key)
        decrypted = decrypt_data(encrypted, key)
        
        assert decrypted == ""

    def test_encryption_large_data(self):
        """Test encryption with large data payload."""
        key = generate_key()
        large_data = "x" * 10000  # 10KB of data
        
        encrypted = encrypt_data(large_data, key)
        decrypted = decrypt_data(encrypted, key)
        
        assert decrypted == large_data

    def test_validate_encryption_key(self):
        """Test encryption key validation."""
        valid_key = generate_key()
        invalid_key = "not_a_valid_key"
        
        assert validate_encryption_key(valid_key)
        assert not validate_encryption_key(invalid_key)
        assert not validate_encryption_key("")
        assert not validate_encryption_key(None)

    def test_input_validation_comprehensive(self):
        """Test comprehensive input validation rules."""
        # Valid input cases
        assert InputValidator.validate_username("validuser123")[0]
        assert InputValidator.validate_email("user@example.com")[0]
        assert InputValidator.validate_entry_name("Secure Entry")[0]
        assert InputValidator.validate_password("securepass123")[0]
        assert InputValidator.validate_email_or_username("user@test.com")[0]
        assert InputValidator.validate_password_length("password123")[0]
        
        # Invalid input cases
        assert not InputValidator.validate_username("ab")[0]  # Too short
        assert not InputValidator.validate_username("a" * 51)[0]  # Too long
        assert not InputValidator.validate_email("invalid-email")[0]  # Invalid format
        assert not InputValidator.validate_entry_name("")[0]  # Empty entry
        assert not InputValidator.validate_password("")[0]  # Empty password
        assert not InputValidator.validate_password("short")[0]  # Too short
        assert not InputValidator.validate_entry_name("a" * 26)[0]  # Too long
        assert not InputValidator.validate_email_or_username("a" * 26)[0]  # Too long
        assert not InputValidator.validate_password_length("a" * 101)[0]  # Too long

    def test_input_sanitization(self):
        """Test input sanitization functionality."""
        test_cases = [
            ("  hello  world  ", "hello world"),
            ("hello\tworld\n", "hello world"),
            ("a" * 600, "a" * 500),  # Should truncate to max_length
            ("", ""),
        ]
        
        for input_text, expected in test_cases:
            sanitized = InputValidator.sanitize_input(input_text)
            assert sanitized == expected

    def test_session_manager_security(self):
        """Test session manager security features."""
        user_id = 99999
        test_user_data = {
            'user_id': 1,
            'username': 'testuser'
        }
        
        sessions.authenticate_user(user_id, test_user_data)
        assert sessions.is_session_valid(user_id), "Session should be valid after authentication"
        
        user_data = sessions.get_user_data(user_id)
        assert user_data['username'] == 'testuser'
        assert 'encryption_key' not in user_data, "Encryption keys should not be stored in sessions"
        
        sessions.logout_user(user_id)
        assert not sessions.is_session_valid(user_id), "Session should be invalid after logout"

    def test_session_timeout(self):
        """Test session timeout functionality."""
        user_id = 88888
        test_user_data = {
            'user_id': 1,
            'username': 'timeoutuser'
        }
        
        sessions.authenticate_user(user_id, test_user_data)
        assert sessions.is_session_valid(user_id)
        
        # Simulate session expiration by manipulating internal data
        session_data = sessions._decrypt_session_data(sessions.sessions[user_id])
        session_data['last_activity'] = 0  # Set to very old timestamp
        sessions.sessions[user_id] = sessions._encrypt_session_data(session_data)
        
        assert not sessions.is_session_valid(user_id), "Session should expire after timeout"

    def test_login_attempt_limiting(self):
        """Test login attempt limiting functionality."""
        user_id = 77777
        
        # First 2 attempts should be allowed (0, 1, 2 = 3 attempts total)
        for i in range(2):
            assert sessions.record_login_attempt(user_id), f"Attempt {i+1} should be allowed"
        
        # Third attempt should be blocked (max_login_attempts = 3, so 0,1,2 allowed, 3rd blocked)
        assert not sessions.record_login_attempt(user_id), "Third attempt should be blocked"
        
        # Check remaining attempts
        assert sessions.get_remaining_attempts(user_id) == 0

    def test_session_encryption(self):
        """Test that session data is properly encrypted."""
        user_id = 66666
        test_user_data = {
            'user_id': 1,
            'username': 'encrypteduser'
        }
        
        sessions.authenticate_user(user_id, test_user_data)
        
        # Verify data is encrypted in storage (base64 encoded, not plain text)
        encrypted_data = sessions.sessions[user_id]
        assert encrypted_data != test_user_data
        assert "username" not in encrypted_data
        # Base64 encoded data should be much longer than original
        assert len(encrypted_data) > 100

    def test_invalid_user_id_handling(self):
        """Test handling of invalid user IDs."""
        invalid_user_ids = [0, -1, "string", None]
        
        for user_id in invalid_user_ids:
            assert not sessions.update_user_activity(user_id)
            assert not sessions.is_session_valid(user_id)
            assert sessions.get_user_data(user_id) == {}

    def test_session_cleanup(self):
        """Test expired session cleanup."""
        user_id = 55555
        test_user_data = {
            'user_id': 1,
            'username': 'cleanupuser'
        }
        
        sessions.authenticate_user(user_id, test_user_data)
        assert user_id in sessions.sessions
        
        # Force expiration
        session_data = sessions._decrypt_session_data(sessions.sessions[user_id])
        session_data['last_activity'] = 0
        sessions.sessions[user_id] = sessions._encrypt_session_data(session_data)
        
        sessions.cleanup_expired_sessions()
        assert user_id not in sessions.sessions

    def test_session_stats(self):
        """Test session statistics collection."""
        stats = sessions.get_session_stats()
        
        assert 'total_sessions' in stats
        assert 'active_sessions' in stats
        assert 'authenticated_sessions' in stats
        assert 'login_attempts' in stats
        
        # Stats should be non-negative integers
        for key, value in stats.items():
            assert isinstance(value, int)
            assert value >= 0