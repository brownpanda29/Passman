import random
import string
import hashlib
import os
import re
import math
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Common passwords and patterns for security analysis
COMMON_PASSWORDS = [
    "password", "123456", "123456789", "qwerty", "abc123", "111111", "dragon",
    "master", "monkey", "letmein", "login", "princess", "qwertyuiop", "solo",
    "passw0rd", "starwars", "password123", "admin", "welcome", "root", "user",
    "guest", "test", "12345", "123123", "password1", "qwerty123", "123qwe"
]

KEYBOARD_PATTERNS = [
    "qwerty", "asdf", "zxcv", "1234", "abcd", "qwertyuiop", "asdfghjkl",
    "zxcvbnm", "1234567890", "!@#$%^&*()", "098765", "mnbvcxz"
]

def generate_password(length=12):
    """Generate a strong random password
    
    Args:
        length (int): Length of password (default 12)
    
    Returns:
        str: Generated password
    """
    if length < 8:
        length = 8
    elif length > 20:
        length = 20
    
    # Character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Ensure at least one character from each set
    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(symbols)
    ]
    
    # Fill remaining length with random characters from all sets
    all_chars = lowercase + uppercase + digits + symbols
    for _ in range(length - 4):
        password.append(random.choice(all_chars))
    
    # Shuffle the password list
    random.shuffle(password)
    
    return ''.join(password)

def hash_password(password):
    """Hash password using SHA-256
    
    Args:
        password (str): Password to hash
    
    Returns:
        str: Hashed password
    """
    return hashlib.sha256(password.encode()).hexdigest()

def derive_key(password, salt):
    """Derive encryption key from password using PBKDF2
    
    Args:
        password (str): Master password
        salt (bytes): Salt for key derivation
    
    Returns:
        bytes: Derived key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_data(data, password):
    """Encrypt data using master password
    
    Args:
        data (str): Data to encrypt
        password (str): Master password
    
    Returns:
        bytes: Encrypted data with salt prepended
    """
    # Generate random salt
    salt = os.urandom(16)
    
    # Derive key from password
    key = derive_key(password, salt)
    
    # Create Fernet cipher
    f = Fernet(key)
    
    # Encrypt data
    encrypted_data = f.encrypt(data.encode())
    
    # Prepend salt to encrypted data
    return salt + encrypted_data

def decrypt_data(encrypted_data, password):
    """Decrypt data using master password
    
    Args:
        encrypted_data (bytes): Encrypted data with salt prepended
        password (str): Master password
    
    Returns:
        str: Decrypted data
    """
    if len(encrypted_data) < 16:
        raise ValueError("Invalid encrypted data")
    
    # Extract salt and encrypted data
    salt = encrypted_data[:16]
    encrypted_content = encrypted_data[16:]
    
    # Derive key from password
    key = derive_key(password, salt)
    
    # Create Fernet cipher
    f = Fernet(key)
    
    # Decrypt data
    decrypted_data = f.decrypt(encrypted_content)
    
    return decrypted_data.decode()

def analyze_password_strength(password):
    """Analyze password strength using AI-like algorithms
    
    Args:
        password (str): Password to analyze
    
    Returns:
        dict: Analysis results including strength, score, crack time, issues, and recommendations
    """
    if not password:
        return {
            'strength': 'Invalid',
            'score': 0,
            'crack_time': 'N/A',
            'color': [1, 0, 0],  # Red
            'issues': ['Password is empty'],
            'recommendations': ['Enter a password']
        }
    
    score = 0
    issues = []
    recommendations = []
    
    # Length analysis
    length = len(password)
    if length < 8:
        issues.append(f"Too short ({length} characters)")
        recommendations.append("Use at least 8 characters")
    elif length < 12:
        score += 15
        recommendations.append("Consider using 12+ characters for better security")
    elif length < 16:
        score += 25
    else:
        score += 35
    
    # Character variety analysis
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password))
    
    char_variety = sum([has_lower, has_upper, has_digit, has_special])
    
    if char_variety == 1:
        issues.append("Uses only one character type")
        recommendations.append("Mix uppercase, lowercase, numbers, and symbols")
    elif char_variety == 2:
        score += 10
        recommendations.append("Add more character types (symbols, numbers)")
    elif char_variety == 3:
        score += 20
        recommendations.append("Add symbols for maximum security")
    else:
        score += 30
    
    # Pattern analysis
    has_common_patterns = False
    for pattern in KEYBOARD_PATTERNS:
        if pattern.lower() in password.lower():
            has_common_patterns = True
            issues.append(f"Contains keyboard pattern: {pattern}")
            break
    
    if has_common_patterns:
        recommendations.append("Avoid keyboard patterns")
    else:
        score += 10
    
    # Common password check
    is_common = False
    for common in COMMON_PASSWORDS:
        if common.lower() in password.lower():
            is_common = True
            issues.append("Contains common password elements")
            break
    
    if is_common:
        recommendations.append("Avoid common passwords and dictionary words")
    else:
        score += 15
    
    # Repetition analysis
    has_repetition = bool(re.search(r'(.)\1{2,}', password))  # 3+ repeated chars
    if has_repetition:
        issues.append("Contains repeated characters")
        recommendations.append("Avoid character repetition")
    else:
        score += 10
    
    # Sequential analysis
    has_sequential = False
    for i in range(len(password) - 2):
        if len(password[i:i+3]) == 3:
            chars = password[i:i+3]
            if (ord(chars[1]) == ord(chars[0]) + 1 and 
                ord(chars[2]) == ord(chars[1]) + 1):
                has_sequential = True
                break
    
    if has_sequential:
        issues.append("Contains sequential characters")
        recommendations.append("Avoid sequential patterns like 'abc' or '123'")
    else:
        score += 10
    
    # Calculate entropy and crack time
    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 32
    
    if charset_size == 0:
        charset_size = 1
    
    entropy = length * math.log2(charset_size)
    
    # Estimate crack time (assuming 1 billion guesses per second)
    combinations = charset_size ** length
    crack_time_seconds = combinations / (2 * 1_000_000_000)  # Average case
    
    # Convert to human readable time
    crack_time_str = format_time(crack_time_seconds)
    
    # Determine strength level
    if score >= 80:
        strength = "Very Strong"
        color = [0, 0.8, 0]  # Green
    elif score >= 60:
        strength = "Strong"
        color = [0.5, 0.8, 0]  # Light green
    elif score >= 40:
        strength = "Good"
        color = [0.8, 0.8, 0]  # Yellow
    elif score >= 20:
        strength = "Weak"
        color = [1, 0.5, 0]  # Orange
    else:
        strength = "Very Weak"
        color = [1, 0, 0]  # Red
    
    # Add specific recommendations based on score
    if score < 40:
        recommendations.append("This password is easily hackable")
    elif score < 60:
        recommendations.append("Consider making it stronger")
    
    if not recommendations:
        recommendations.append("Password looks secure!")
    
    return {
        'strength': strength,
        'score': min(score, 100),
        'crack_time': crack_time_str,
        'color': color,
        'issues': issues,
        'recommendations': recommendations,
        'entropy': entropy
    }

def format_time(seconds):
    """Format seconds into human readable time"""
    if seconds < 1:
        return "Less than 1 second"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f} days"
    elif seconds < 31536000000:
        return f"{seconds/31536000:.1f} years"
    else:
        return "More than 1000 years"

