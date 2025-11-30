import pytest
import asyncio
from unittest.mock import AsyncMock, patch, ANY
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from handlers.password_entry import (
    process_entry_name, process_new_email, process_password,
    process_new_name_edit, process_new_email_edit, process_new_password_edit,
    decrypt_with_key
)


class TestPasswordEntries:
    """Password entry management tests"""
    
    @pytest.mark.asyncio
    async def test_valid_entry_name(self):
        """Test successful entry name validation."""
        message = AsyncMock()
        message.text = "Gmail Account"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.update_data = AsyncMock()
        state.set_state = AsyncMock()
        
        await process_entry_name(message, state)
        
        state.update_data.assert_called_with(entry_name="Gmail Account")
        state.set_state.assert_called_once()

    @pytest.mark.asyncio
    async def test_entry_name_too_long(self):
        """Test rejection of entry name that exceeds 25 characters."""
        message = AsyncMock()
        message.text = "A" * 26
        message.answer = AsyncMock()
        
        state = AsyncMock()
        
        await process_entry_name(message, state)
        
        message.answer.assert_called_with("🔸 Entry name should be less than 25 characters. Please try a shorter name\n\nPlease enter a valid entry name:")

    @pytest.mark.asyncio
    async def test_entry_name_too_short(self):
        """Test rejection of entry name that is too short."""
        message = AsyncMock()
        message.text = "A"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        
        await process_entry_name(message, state)
        
        message.answer.assert_called_with("🔸 Entry name must be at least 2 characters long\n\nPlease enter a valid entry name:")

    @pytest.mark.asyncio
    async def test_entry_name_invalid_chars(self):
        """Test rejection of entry name with invalid characters."""
        invalid_names = ["Test;Entry", "Test'Entry", "Test\\Entry", "Test/Entry"]
        
        for name in invalid_names:
            message = AsyncMock()
            message.text = name
            message.answer = AsyncMock()
            
            state = AsyncMock()
            
            await process_entry_name(message, state)
            
            message.answer.assert_called_with("🔸 Entry name contains invalid characters\n\nPlease enter a valid entry name:")

    @pytest.mark.asyncio
    async def test_empty_entry_name(self):
        """Test rejection of empty entry name."""
        message = AsyncMock()
        message.text = ""
        message.answer = AsyncMock()
        
        state = AsyncMock()
        
        await process_entry_name(message, state)
        
        message.answer.assert_called_with("🔸 Entry name cannot be empty\n\nPlease enter a valid entry name:")

    @pytest.mark.asyncio
    async def test_valid_email_input(self):
        """Test successful email/username validation."""
        message = AsyncMock()
        message.text = "user@example.com"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {'entry_name': 'Test Entry'}
        state.update_data = AsyncMock()
        state.set_state = AsyncMock()
        
        await process_new_email(message, state)
        
        state.update_data.assert_called_with(email="user@example.com")
        state.set_state.assert_called_once()

    @pytest.mark.asyncio
    async def test_email_too_long(self):
        """Test rejection of email that exceeds 25 characters."""
        message = AsyncMock()
        message.text = "a" * 26
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {'entry_name': 'Test Entry'}
        
        await process_new_email(message, state)
        
        message.answer.assert_called_with("🔸 Email or username should be less than 25 characters. Please try a shorter one\n\nPlease enter a valid email or username:")

    @pytest.mark.asyncio
    async def test_empty_email(self):
        """Test rejection of empty email/username."""
        message = AsyncMock()
        message.text = ""
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {'entry_name': 'Test Entry'}
        
        await process_new_email(message, state)
        
        message.answer.assert_called_with("🔸 Email or username cannot be empty\n\nPlease enter a valid email or username:")

    @pytest.mark.asyncio
    async def test_valid_password_input(self):
        """Test successful password entry creation."""
        message = AsyncMock()
        message.text = "mypassword123"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {
            'entry_name': 'Test Entry',
            'email': 'user@example.com'
        }
        state.clear = AsyncMock()
        
        with patch('handlers.password_entry.sessions') as mock_sessions, \
             patch('handlers.password_entry.db') as mock_db, \
             patch('handlers.password_entry.encrypt_data') as mock_encrypt:
            
            mock_sessions.get_user_data.return_value = {'username': 'testuser'}
            mock_db.get_user_by_username.return_value = {
                'id': 1, 'encryption_key': 'test_key'
            }
            mock_encrypt.return_value = 'encrypted_data'
            mock_db.create_password_entry.return_value = True
            
            await process_password(message, state)
            
            mock_db.create_password_entry.assert_called_once()
            message.answer.assert_called_with(
                "✅ Password entry saved successfully!\n\n📝 Entry: Test Entry",
                reply_markup=ANY
            )

    @pytest.mark.asyncio
    async def test_password_too_long(self):
        """Test rejection of password that exceeds 100 characters."""
        message = AsyncMock()
        message.text = "a" * 101
        message.answer = AsyncMock()
        
        state = AsyncMock()
        
        await process_password(message, state)
        
        message.answer.assert_called_with("🔸 Password should be less than 100 characters. Please try a shorter password\n\nPlease enter a valid password:")

    @pytest.mark.asyncio
    async def test_empty_password(self):
        """Test rejection of empty password."""
        message = AsyncMock()
        message.text = ""
        message.answer = AsyncMock()
        
        state = AsyncMock()
        
        await process_password(message, state)
        
        message.answer.assert_called_with("🔸 Password cannot be empty\n\nPlease enter a valid password:")

    @pytest.mark.asyncio
    async def test_database_error_password_entry(self):
        """Test handling of database errors during password entry creation."""
        message = AsyncMock()
        message.text = "mypassword123"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {
            'entry_name': 'Test Entry',
            'email': 'user@example.com'
        }
        
        with patch('handlers.password_entry.sessions') as mock_sessions, \
             patch('handlers.password_entry.db') as mock_db, \
             patch('handlers.password_entry.encrypt_data') as mock_encrypt:
            
            mock_sessions.get_user_data.return_value = {'username': 'testuser'}
            mock_db.get_user_by_username.return_value = {
                'id': 1, 'encryption_key': 'test_key'
            }
            mock_encrypt.return_value = 'encrypted_data'
            mock_db.create_password_entry.return_value = False
            
            await process_password(message, state)
            
            message.answer.assert_called_with(
                "❌ Failed to save password entry. Please try again.",
                reply_markup=ANY
            )

    @pytest.mark.asyncio
    async def test_edit_entry_name_valid(self, mock_db):
        """Test successful entry name editing."""
        message = AsyncMock()
        message.text = "New Entry Name"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {'editing_entry_id': 1}
        
        with patch('handlers.password_entry.sessions') as mock_sessions, \
             patch('handlers.password_entry.db') as mock_db:
            
            mock_sessions.get_user_data.return_value = {'username': 'testuser'}
            mock_db.get_user_by_username.return_value = {'id': 1}
            mock_db.update_password_entry.return_value = True
            
            await process_new_name_edit(message, state)
            
            mock_db.update_password_entry.assert_called_once()
            # After edit, it calls view_password_entry_after_edit which sends different message
            assert message.answer.called

    @pytest.mark.asyncio
    async def test_edit_entry_name_too_long(self):
        """Test rejection of edited entry name that exceeds 25 characters."""
        message = AsyncMock()
        message.text = "A" * 26
        message.answer = AsyncMock()
        
        state = AsyncMock()
        
        await process_new_name_edit(message, state)
        
        message.answer.assert_called_with("🔸 Entry name should be less than 25 characters. Please try a shorter name\n\nPlease enter a valid entry name:")

    @pytest.mark.asyncio
    async def test_edit_email_valid(self, mock_db):
        """Test successful email editing."""
        message = AsyncMock()
        message.text = "new@example.com"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {
            'editing_entry_id': 1,
            'encryption_key': 'test_key'
        }
        
        with patch('handlers.password_entry.sessions') as mock_sessions, \
             patch('handlers.password_entry.db') as mock_db, \
             patch('handlers.password_entry.encrypt_data') as mock_encrypt:
            
            mock_sessions.get_user_data.return_value = {'username': 'testuser'}
            mock_db.get_user_by_username.return_value = {'id': 1}
            mock_encrypt.return_value = 'encrypted_email'
            mock_db.update_password_entry.return_value = True
            
            await process_new_email_edit(message, state)
            
            mock_db.update_password_entry.assert_called_once()
            # After edit, it calls view_password_entry_after_edit which sends different message
            assert message.answer.called

    @pytest.mark.asyncio
    async def test_edit_email_too_long(self):
        """Test rejection of edited email that exceeds 25 characters."""
        message = AsyncMock()
        message.text = "a" * 26
        message.answer = AsyncMock()
        
        state = AsyncMock()
        
        await process_new_email_edit(message, state)
        
        message.answer.assert_called_with("🔸 Email or username should be less than 25 characters. Please try a shorter one\n\nPlease enter a valid email or username:")

    @pytest.mark.asyncio
    async def test_edit_password_valid(self, mock_db):
        """Test successful password editing."""
        message = AsyncMock()
        message.text = "newpassword123"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {
            'editing_entry_id': 1,
            'encryption_key': 'test_key'
        }
        
        with patch('handlers.password_entry.sessions') as mock_sessions, \
             patch('handlers.password_entry.db') as mock_db, \
             patch('handlers.password_entry.encrypt_data') as mock_encrypt:
            
            mock_sessions.get_user_data.return_value = {'username': 'testuser'}
            mock_db.get_user_by_username.return_value = {'id': 1}
            mock_encrypt.return_value = 'encrypted_password'
            mock_db.update_password_entry.return_value = True
            
            await process_new_password_edit(message, state)
            
            mock_db.update_password_entry.assert_called_once()
            # After edit, it calls view_password_entry_after_edit which sends different message
            assert message.answer.called

    @pytest.mark.asyncio
    async def test_edit_password_too_long(self):
        """Test rejection of edited password that exceeds 100 characters."""
        message = AsyncMock()
        message.text = "a" * 101
        message.answer = AsyncMock()
        
        state = AsyncMock()
        
        await process_new_password_edit(message, state)
        
        message.answer.assert_called_with("🔸 Password should be less than 100 characters. Please try a shorter password\n\nPlease enter a valid password:")

    @pytest.mark.asyncio
    async def test_decrypt_with_valid_key(self):
        """Test successful decryption with valid encryption key."""
        message = AsyncMock()
        message.text = "valid_encryption_key"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {'current_entry_id': 1}
        
        with patch('handlers.password_entry.sessions') as mock_sessions, \
             patch('handlers.password_entry.db') as mock_db, \
             patch('handlers.password_entry.decrypt_data') as mock_decrypt:
            
            mock_sessions.get_user_data.return_value = {'username': 'testuser'}
            mock_db.get_user_by_username.return_value = {'id': 1}
            mock_db.get_password_entry.return_value = {
                'id': 1, 'entry_name': 'Test Entry', 'email': 'encrypted_email', 'password': 'encrypted_password'
            }
            mock_decrypt.side_effect = ['decrypted_email', 'decrypted_password']
            
            await decrypt_with_key(message, state)
            
            # Should send decrypted data first, then action menu
            assert message.answer.call_count >= 2

    @pytest.mark.asyncio
    async def test_decrypt_with_invalid_key(self):
        """Test handling of invalid encryption key during decryption."""
        message = AsyncMock()
        message.text = "invalid_encryption_key"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {'current_entry_id': 1}
        
        with patch('handlers.password_entry.sessions') as mock_sessions, \
             patch('handlers.password_entry.db') as mock_db, \
             patch('handlers.password_entry.decrypt_data') as mock_decrypt:
            
            mock_sessions.get_user_data.return_value = {'username': 'testuser'}
            mock_db.get_user_by_username.return_value = {'id': 1}
            mock_db.get_password_entry.return_value = {
                'id': 1, 'entry_name': 'Test Entry'
            }
            mock_decrypt.side_effect = Exception("Invalid key")
            
            await decrypt_with_key(message, state)
            
            message.answer.assert_called_with(
                "❌ Invalid encryption key. Please try again.",
                reply_markup=ANY
            )