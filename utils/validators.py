import re
import logging
from typing import Tuple

logger = logging.getLogger(__name__)


class InputValidator:
    """Comprehensive input validation for security and data integrity."""
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        """Validate username format and security requirements.
        
        Args:
            username: Username string to validate
            
        Returns:
            Tuple of (is_valid, message_or_username)
        """
        if not username or not username.strip():
            return False, "Username cannot be empty"
        
        username = username.strip()
        
        if len(username) < 3:
            return False, "Username must be at least 3 characters long"
        if len(username) > 50:
            return False, "Username cannot exceed 50 characters"
        
        if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            return False, "Username can only contain letters, numbers, and . _ - symbols"
        
        reserved_names = ['admin', 'root', 'system', 'bot', 'telegram']
        if username.lower() in reserved_names:
            return False, "This username is not available"
        
        return True, username
    
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, str]:
        """Validate password strength and length requirements.
        
        Args:
            password: Password string to validate
            
        Returns:
            Tuple of (is_valid, message_or_password)
        """
        if not password:
            return False, "Password cannot be empty"
        
        if len(password) < 6:
            return False, "Password must be at least 6 characters long"
        if len(password) > 128:
            return False, "Password cannot exceed 128 characters"
        
        return True, password
    
    @staticmethod
    def validate_entry_name(name: str) -> Tuple[bool, str]:
        """Validate password entry name format and security.
        
        Args:
            name: Entry name string to validate
            
        Returns:
            Tuple of (is_valid, message_or_name)
        """
        if not name or not name.strip():
            return False, "Entry name cannot be empty"
        
        name = name.strip()
        
        if len(name) < 2:
            return False, "Entry name must be at least 2 characters long"
        if len(name) > 25:
            return False, "Entry name should be less than 25 characters. Please try a shorter name"
        
        invalid_chars = [';', '"', "'", '\\', '/', '<', '>']
        if any(char in name for char in invalid_chars):
            return False, "Entry name contains invalid characters"
        
        return True, name
    
    @staticmethod
    def validate_email(email: str) -> Tuple[bool, str]:
        """Validate email address format and length.
        
        Args:
            email: Email address string to validate
            
        Returns:
            Tuple of (is_valid, message_or_email)
        """
        if not email or not email.strip():
            return False, "Email address cannot be empty"
        
        email = email.strip()
        
        if len(email) > 25:
            return False, "Email should be less than 25 characters. Please try a shorter email"
        
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return False, "Please enter a valid email address format"
        
        return True, email
    
    @staticmethod
    def validate_email_or_username(input_str: str) -> Tuple[bool, str]:
        """Validate email or username input for password entries.
        
        Args:
            input_str: Email or username string to validate
            
        Returns:
            Tuple of (is_valid, message_or_input)
        """
        if not input_str or not input_str.strip():
            return False, "Email or username cannot be empty"
        
        input_str = input_str.strip()
        
        if len(input_str) > 25:
            return False, "Email or username should be less than 25 characters. Please try a shorter one"
        
        return True, input_str
    
    @staticmethod
    def validate_password_length(password: str) -> Tuple[bool, str]:
        """Validate password length for password entries.
        
        Args:
            password: Password string to validate
            
        Returns:
            Tuple of (is_valid, message_or_password)
        """
        if not password:
            return False, "Password cannot be empty"
        
        if len(password) > 100:
            return False, "Password should be less than 100 characters. Please try a shorter password"
        
        return True, password
    
    @staticmethod
    def validate_encryption_key(key: str) -> Tuple[bool, str]:
        """Validate encryption key format and structure.
        
        Args:
            key: Encryption key string to validate
            
        Returns:
            Tuple of (is_valid, message_or_key)
        """
        if not key or not key.strip():
            return False, "Encryption key cannot be empty"
        
        key = key.strip()
        
        try:
            import base64
            base64.b64decode(key)
            return True, key
        except Exception:
            return False, "Invalid encryption key format"
    
    @staticmethod
    def sanitize_input(text: str, max_length: int = 500) -> str:
        """Sanitize user input to prevent injection attacks.
        
        Args:
            text: Input text to sanitize
            max_length: Maximum allowed length for input
            
        Returns:
            Sanitized and truncated text
        """
        if not text:
            return ""
        
        text = ' '.join(text.split())
        
        if len(text) > max_length:
            text = text[:max_length]
        
        return text