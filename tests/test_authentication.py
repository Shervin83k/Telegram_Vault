import pytest
import asyncio
from unittest.mock import AsyncMock, patch, ANY
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from handlers.auth import process_username, process_password


class TestAuthentication:
    """Comprehensive authentication system tests"""
    
    @pytest.mark.asyncio
    async def test_valid_username_signup(self, mock_db):
        """Test successful username validation during signup."""
        message = AsyncMock()
        message.text = "validuser123"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {'is_signup': True}
        state.update_data = AsyncMock()
        state.set_state = AsyncMock()
        
        await process_username(message, state)
        
        state.set_state.assert_called_once()
        message.answer.assert_called_with(
            "🔑 Please enter your password:\n\nRequirements:\n• Minimum 6 characters\n• Maximum 128 characters\n\nUse 'Cancel' or /cancel to return to main menu",
            reply_markup=ANY
        )

    @pytest.mark.asyncio
    async def test_existing_username_signup(self, mock_db):
        """Test rejection of existing username during signup."""
        mock_db.username_exists.return_value = True
        
        message = AsyncMock()
        message.text = "existinguser"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {'is_signup': True}
        
        await process_username(message, state)
        
        message.answer.assert_called_with(
            "❌ Username 'existinguser' is already registered.\n\nPlease choose a different username:",
            reply_markup=ANY
        )

    @pytest.mark.asyncio
    async def test_username_too_short(self):
        """Test rejection of username that is too short."""
        message = AsyncMock()
        message.text = "ab"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        
        await process_username(message, state)
        
        message.answer.assert_called_with("❌ Username must be between 3 and 50 characters:")

    @pytest.mark.asyncio
    async def test_username_too_long(self):
        """Test rejection of username that is too long."""
        message = AsyncMock()
        message.text = "a" * 51
        message.answer = AsyncMock()
        
        state = AsyncMock()
        
        await process_username(message, state)
        
        message.answer.assert_called_with("❌ Username must be between 3 and 50 characters:")

    @pytest.mark.asyncio
    async def test_username_invalid_chars(self):
        """Test rejection of username with invalid characters."""
        message = AsyncMock()
        message.text = "user@name"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        
        await process_username(message, state)
        
        message.answer.assert_called_with("❌ Username can only contain letters, numbers, and underscores:")

    @pytest.mark.asyncio
    async def test_empty_username(self):
        """Test proper handling of empty username input."""
        message = AsyncMock()
        message.text = ""
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {'is_signup': True}
        
        await process_username(message, state)
        
        message.answer.assert_called_with("❌ Please enter a valid username:")

    @pytest.mark.asyncio
    async def test_valid_password_signup(self, mock_db):
        """Test successful password validation during signup."""
        message = AsyncMock()
        message.text = "securepassword123"
        message.from_user.id = 12345
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {
            'username': 'testuser',
            'is_signup': True
        }
        state.set_state = AsyncMock()
        
        await process_password(message, state)
        
        mock_db.create_user.assert_called_once()
        state.set_state.assert_called_once()

    @pytest.mark.asyncio
    async def test_password_too_short(self):
        """Test rejection of password that is too short."""
        message = AsyncMock()
        message.text = "123"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {'is_signup': True}
        
        await process_password(message, state)
        
        message.answer.assert_called_with("❌ Password must be at least 6 characters:")

    @pytest.mark.asyncio
    async def test_password_too_long(self):
        """Test rejection of password that is too long."""
        message = AsyncMock()
        message.text = "a" * 129
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {'is_signup': True}
        
        await process_password(message, state)
        
        message.answer.assert_called_with("❌ Password must be less than 128 characters:")

    @pytest.mark.asyncio
    async def test_empty_password(self):
        """Test proper handling of empty password input."""
        message = AsyncMock()
        message.text = ""
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {'is_signup': True}
        
        await process_password(message, state)
        
        message.answer.assert_called_with("❌ Please enter a valid password:")

    @pytest.mark.asyncio
    async def test_database_error_on_signup(self, mock_db):
        """Test handling of database errors during user registration."""
        mock_db.create_user.return_value = False
        
        message = AsyncMock()
        message.text = "securepassword123"
        message.from_user.id = 12345
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {
            'username': 'testuser',
            'is_signup': True
        }
        
        await process_password(message, state)
        
        assert message.answer.called
        call_args = message.answer.call_args[0]
        assert "❌ Account creation failed" in call_args[0]

    @pytest.mark.asyncio
    async def test_cancel_operation_username(self):
        """Test cancellation during username entry."""
        message = AsyncMock()
        message.text = "cancel"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        
        with patch('handlers.auth.cancel_operation') as mock_cancel:
            await process_username(message, state)
            mock_cancel.assert_called_once_with(message, state)

    @pytest.mark.asyncio
    async def test_cancel_operation_password(self):
        """Test cancellation during password entry."""
        message = AsyncMock()
        message.text = "cancel"
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {'is_signup': True}
        
        with patch('handlers.auth.cancel_operation') as mock_cancel:
            await process_password(message, state)
            mock_cancel.assert_called_once_with(message, state)

    @pytest.mark.asyncio
    async def test_username_whitespace_handling(self):
        """Test username input with various whitespace patterns."""
        # Test that whitespace is properly handled (stripped)
        message = AsyncMock()
        message.text = "  user  "
        message.answer = AsyncMock()
        
        state = AsyncMock()
        state.get_data.return_value = {'is_signup': True}
        state.update_data = AsyncMock()
        state.set_state = AsyncMock()
        
        with patch('handlers.auth.db.username_exists') as mock_exists:
            mock_exists.return_value = False
            await process_username(message, state)
            
            # Should process the username (stripped) and proceed to password
            state.set_state.assert_called_once()
            message.answer.assert_called_with(
                "🔑 Please enter your password:\n\nRequirements:\n• Minimum 6 characters\n• Maximum 128 characters\n\nUse 'Cancel' or /cancel to return to main menu",
                reply_markup=ANY
            )