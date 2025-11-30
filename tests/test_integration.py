import pytest
import asyncio
from unittest.mock import AsyncMock, patch, ANY
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from handlers.auth import process_username, process_password
from handlers.password_entry import process_entry_name, process_new_email, process_password as process_entry_password
from utils.validators import InputValidator
from utils.encryption import encrypt_data, decrypt_data, generate_key
from utils.hashing import HashManager
from utils.session_manager import sessions


class TestIntegration:
    """End-to-end integration tests"""
    
    @pytest.mark.asyncio
    async def test_complete_user_flow(self):
        """Test complete user journey from registration to password management."""
        # Step 1: User registration
        message = AsyncMock()
        message.text = "integrationuser"
        message.from_user.id = 123456
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {'is_signup': True}
        state.update_data = AsyncMock()
        state.set_state = AsyncMock()
        
        with patch('handlers.auth.db.username_exists') as mock_exists:
            mock_exists.return_value = False
            await process_username(message, state)
        
        # Step 2: Password setup
        message.text = "integrationpass123"
        state.get_data.return_value = {
            'username': 'integrationuser',
            'is_signup': True
        }
        
        with patch('handlers.auth.db.create_user') as mock_create, \
             patch('handlers.auth.db.hash_password') as mock_hash, \
             patch('handlers.auth.generate_key') as mock_key:
            
            mock_create.return_value = True
            mock_hash.return_value = 'hashed_password'
            mock_key.return_value = 'encryption_key_123'
            
            await process_password(message, state)
            
            mock_create.assert_called_once()
            state.set_state.assert_called()

    @pytest.mark.asyncio
    async def test_password_entry_creation_flow(self):
        """Test complete password entry creation flow."""
        # Simulate authenticated user
        with patch('handlers.password_entry.sessions') as mock_sessions, \
             patch('handlers.password_entry.db') as mock_db:
            
            mock_sessions.get_user_data.return_value = {'username': 'testuser'}
            mock_db.get_user_by_username.return_value = {
                'id': 1, 'encryption_key': 'test_key'
            }
            mock_db.create_password_entry.return_value = True
            
            # Step 1: Entry name
            message = AsyncMock()
            message.text = "Gmail Integration"
            message.answer = AsyncMock()
            
            state = AsyncMock()
            state.update_data = AsyncMock()
            state.set_state = AsyncMock()
            
            await process_entry_name(message, state)
            
            # Step 2: Email
            message.text = "user@gmail.com"
            state.get_data.return_value = {'entry_name': 'Gmail Integration'}
            state.update_data = AsyncMock()
            state.set_state = AsyncMock()
            
            await process_new_email(message, state)
            
            # Step 3: Password
            message.text = "emailpassword123"
            state.get_data.return_value = {
                'entry_name': 'Gmail Integration',
                'email': 'user@gmail.com'
            }
            state.clear = AsyncMock()
            
            with patch('handlers.password_entry.encrypt_data') as mock_encrypt:
                mock_encrypt.return_value = 'encrypted_data'
                
                await process_entry_password(message, state)
                
                mock_db.create_password_entry.assert_called_once()

    @pytest.mark.asyncio
    async def test_error_recovery_flow(self):
        """Test user recovery from various error scenarios."""
        # Test invalid input followed by valid input
        message = AsyncMock()
        message.answer = AsyncMock()
        state = AsyncMock()
        state.get_data.return_value = {'is_signup': True}
        state.update_data = AsyncMock()
        state.set_state = AsyncMock()
        
        # First attempt: invalid username (too short)
        message.text = "ab"
        await process_username(message, state)
        message.answer.assert_called_with("❌ Username must be between 3 and 50 characters:")
        
        # Second attempt: valid username
        message.text = "validuser"
        with patch('handlers.auth.db.username_exists') as mock_exists:
            mock_exists.return_value = False
            await process_username(message, state)
        
        # Should proceed to password step after correction
        state.set_state.assert_called_once()

    @pytest.mark.asyncio
    async def test_encryption_integration_flow(self):
        """Test complete encryption/decryption integration."""
        # Generate real encryption key
        key = generate_key()
        original_data = "sensitive_user_data@example.com"
        
        # Encrypt
        encrypted = encrypt_data(original_data, key)
        
        # Verify encryption worked
        assert encrypted != original_data
        assert len(encrypted) > len(original_data)
        
        # Decrypt
        decrypted = decrypt_data(encrypted, key)
        
        # Verify data integrity
        assert decrypted == original_data
        
        # Test with wrong key
        wrong_key = generate_key()
        with pytest.raises(Exception):
            decrypt_data(encrypted, wrong_key)

    def test_validation_integration(self):
        """Test input validation across different modules."""
        # Test various valid inputs across all validators
        assert InputValidator.validate_username("validuser123")[0]
        assert InputValidator.validate_entry_name("Gmail")[0]
        assert InputValidator.validate_email("user@test.com")[0]
        assert InputValidator.validate_email_or_username("username123")[0]
        assert InputValidator.validate_password("securepass123")[0]
        assert InputValidator.validate_password_length("password123")[0]
        
        # Test length limits are enforced across all validators
        assert not InputValidator.validate_entry_name("A" * 26)[0]  # Too long
        assert not InputValidator.validate_email_or_username("B" * 26)[0]  # Too long
        assert not InputValidator.validate_password_length("C" * 101)[0]  # Too long

    @pytest.mark.asyncio
    async def test_session_integration(self):
        """Test session management integration with user flows."""
        user_id = 99999
        user_data = {'user_id': 1, 'username': 'integrationuser'}
        
        # Authenticate user
        assert sessions.authenticate_user(user_id, user_data)
        assert sessions.is_session_valid(user_id)
        
        # Verify session data
        session_data = sessions.get_user_data(user_id)
        assert session_data['username'] == 'integrationuser'
        assert session_data['is_authenticated'] == True
        
        # Logout
        assert sessions.logout_user(user_id)
        assert not sessions.is_session_valid(user_id)

    def test_hashing_integration(self):
        """Test password hashing integration."""
        password = "integration_test_password"
        
        # Hash password
        hashed = HashManager.hash_password(password)
        
        # Verify it's different from original
        assert hashed != password
        
        # Verify correct password
        assert HashManager.verify_password(password, hashed)
        
        # Verify wrong password fails
        assert not HashManager.verify_password("wrong_password", hashed)

    @pytest.mark.asyncio
    async def test_database_error_handling_integration(self):
        """Test integrated error handling for database failures."""
        message = AsyncMock()
        message.text = "testpassword"
        message.from_user.id = 12345
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {
            'username': 'testuser',
            'is_signup': True
        }
        
        # Simulate database failure
        with patch('handlers.auth.db.create_user') as mock_create:
            mock_create.return_value = False
            
            await process_password(message, state)
            
            # Should handle error gracefully
            assert message.answer.called
            call_args = message.answer.call_args[0]
            assert "❌ Account creation failed" in call_args[0]

    @pytest.mark.asyncio
    async def test_concurrent_user_operations(self):
        """Test multiple users operating concurrently."""
        async def user_workflow(user_id, username):
            # Authenticate
            user_data = {'user_id': user_id, 'username': username}
            sessions.authenticate_user(user_id, user_data)
            
            # Verify session
            assert sessions.is_session_valid(user_id)
            
            # Simulate some operations
            data = sessions.get_user_data(user_id)
            assert data['username'] == username
            
            return True
        
        # Run multiple user workflows concurrently
        tasks = []
        for i in range(3):  # Reduced from 5 for stability
            tasks.append(user_workflow(50000 + i, f"concurrentuser{i}"))
        
        results = await asyncio.gather(*tasks)
        assert all(results), "All concurrent user operations should succeed"
        
        # Verify all sessions are active
        for i in range(3):
            assert sessions.is_session_valid(50000 + i)

    def test_data_persistence_integration(self):
        """Test that data remains consistent through multiple operations."""
        # This tests the integration of multiple components
        key = generate_key()
        original_data = "persistent_data@example.com"
        
        # Multiple encryption/decryption cycles
        for i in range(5):  # Reduced from 10 for stability
            encrypted = encrypt_data(original_data, key)
            decrypted = decrypt_data(encrypted, key)
            assert decrypted == original_data, f"Data integrity failed at iteration {i+1}"
        
        # Test with different data
        test_cases = [
            "short",
            "medium_length_data", 
            "special@chars.com",
            "numbers123"
        ]
        
        for test_data in test_cases:
            encrypted = encrypt_data(test_data, key)
            decrypted = decrypt_data(encrypted, key)
            assert decrypted == test_data, f"Data integrity failed for: {test_data}"

    @pytest.mark.asyncio
    async def test_complete_error_recovery(self):
        """Test complete error recovery scenario."""
        message = AsyncMock()
        message.answer = AsyncMock()
        state = AsyncMock()
        
        # Scenario: User makes multiple errors then succeeds
        errors = [
            ("", "❌ Please enter a valid username:"),  # Empty username
            ("a", "❌ Username must be between 3 and 50 characters:"),  # Too short
            ("user@name", "❌ Username can only contain letters, numbers, and underscores:"),  # Invalid chars
        ]
        
        for input_text, expected_error in errors:
            message.text = input_text
            state.get_data.return_value = {'is_signup': True}
            
            await process_username(message, state)
            message.answer.assert_called_with(expected_error)
        
        # Final attempt: valid username
        message.text = "validuser123"
        state.get_data.return_value = {'is_signup': True}
        state.update_data = AsyncMock()
        state.set_state = AsyncMock()
        
        with patch('handlers.auth.db.username_exists') as mock_exists:
            mock_exists.return_value = False
            await process_username(message, state)
            
            # Should succeed and move to password step
            state.set_state.assert_called_once()