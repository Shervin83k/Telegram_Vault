import pytest
import asyncio
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch
from aiogram.fsm.storage.memory import MemoryStorage

# Add project root to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

@pytest.fixture
def storage():
    return MemoryStorage()

@pytest.fixture
def bot():
    return AsyncMock()

@pytest.fixture
def dp(storage):
    return AsyncMock()

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def mock_db():
    """Mock database for all tests"""
    with patch('handlers.auth.db') as mock:
        mock.get_user_by_username.return_value = {
            'id': 1, 'username': 'testuser', 'password_hash': 'hash', 
            'encryption_key': 'test_key', 'telegram_id': 12345
        }
        mock.create_user.return_value = True
        mock.username_exists.return_value = False
        mock.get_password_entries.return_value = []
        mock.create_password_entry.return_value = True
        mock.hash_password.return_value = 'hashed_password'
        mock.get_password_entry.return_value = {
            'id': 1, 'entry_name': 'Test Entry', 'email': 'encrypted_email', 'password': 'encrypted_password'
        }
        mock.update_password_entry.return_value = True
        mock.delete_password_entry.return_value = True
        yield mock

@pytest.fixture
def mock_sessions():
    """Mock session manager"""
    with patch('handlers.auth.sessions') as mock:
        mock.is_session_valid.return_value = True
        mock.get_user_data.return_value = {'username': 'testuser', 'user_id': 1}
        mock.authenticate_user.return_value = True
        yield mock