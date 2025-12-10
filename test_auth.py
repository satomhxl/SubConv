#!/usr/bin/env python3
"""Test script to verify password authentication logic"""

import hmac
import hashlib
import os

# Set the same values as in Vercel
ACCESS_PASSWORD = "7jIR6492cX2TECXyeYReq8"
SECRET_KEY = "77733434f70a34a6c0f52497a5dca6c48d6562ca00c75fd49cdf231c29be9ffc"

def verify_password(password: str) -> bool:
    """Verify the provided password"""
    return hmac.compare_digest(password, ACCESS_PASSWORD)

def generate_access_token(password: str) -> str:
    """Generate a secure access token using HMAC-SHA256"""
    import time
    timestamp = str(int(time.time()))
    message = f"{password}:{timestamp}"
    token = hmac.new(
        SECRET_KEY.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{token}:{timestamp}"

def verify_access_token(token: str) -> bool:
    """Verify the access token"""
    if not token:
        return False
    
    try:
        token_hash, timestamp = token.split(":")
        message = f"{ACCESS_PASSWORD}:{timestamp}"
        expected_token = hmac.new(
            SECRET_KEY.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(token_hash, expected_token)
    except (ValueError, AttributeError):
        return False

# Test
print("Testing password verification...")
print(f"ACCESS_PASSWORD: {ACCESS_PASSWORD}")
print(f"SECRET_KEY: {SECRET_KEY[:20]}...")
print()

# Test 1: Verify password
test_password = "7jIR6492cX2TECXyeYReq8"
result = verify_password(test_password)
print(f"Test 1 - Password verification: {result}")
print(f"  Input: {test_password}")
print(f"  Expected: {ACCESS_PASSWORD}")
print(f"  Match: {test_password == ACCESS_PASSWORD}")
print()

# Test 2: Generate token
token = generate_access_token(test_password)
print(f"Test 2 - Token generation: {token}")
print()

# Test 3: Verify token
token_valid = verify_access_token(token)
print(f"Test 3 - Token verification: {token_valid}")
print()

# Test 4: Test with wrong password
wrong_password = "wrong-password"
result_wrong = verify_password(wrong_password)
print(f"Test 4 - Wrong password verification: {result_wrong}")
print()

print("All tests completed!")
