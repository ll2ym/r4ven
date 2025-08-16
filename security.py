#!/usr/bin/env python3
"""
Security utilities for R4VEN
Contains functions for secure file handling, input validation, and rate limiting
"""

import hashlib
import hmac
import time
import secrets
from collections import defaultdict, deque
from pathlib import Path
from werkzeug.utils import secure_filename
import logging

# Rate limiting storage
rate_limit_storage = defaultdict(deque)

class SecurityError(Exception):
    """Custom exception for security-related errors"""
    pass

def generate_secure_token():
    """Generate a cryptographically secure random token"""
    return secrets.token_urlsafe(32)

def hash_ip_address(ip_address, salt=None):
    """
    Hash IP address for privacy-preserving logging
    Args:
        ip_address (str): IP address to hash
        salt (str): Optional salt for hashing
    Returns:
        str: Hashed IP address
    """
    if salt is None:
        salt = "r4ven_default_salt"
    
    combined = f"{ip_address}{salt}".encode('utf-8')
    return hashlib.sha256(combined).hexdigest()[:16]

def validate_file_content(file_obj):
    """
    Validate file content beyond just extension checking
    Args:
        file_obj: File object to validate
    Returns:
        bool: True if file appears to be a valid image
    """
    try:
        # Check file signature (magic bytes)
        file_obj.seek(0)
        header = file_obj.read(12)
        file_obj.seek(0)
        
        # Common image format signatures
        image_signatures = {
            b'\xff\xd8\xff': 'jpeg',
            b'\x89\x50\x4e\x47': 'png', 
            b'\x47\x49\x46\x38': 'gif',
            b'\x52\x49\x46\x46': 'webp'  # RIFF header for WebP
        }
        
        for signature, format_type in image_signatures.items():
            if header.startswith(signature):
                return True
                
        return False
        
    except Exception as e:
        logging.error(f"File validation error: {str(e)}")
        return False

def sanitize_filename(filename):
    """
    Create a secure filename with additional sanitization
    Args:
        filename (str): Original filename
    Returns:
        str: Sanitized secure filename
    """
    if not filename:
        return "unnamed_file"
    
    # Use werkzeug's secure_filename as base
    safe_name = secure_filename(filename)
    
    # Additional sanitization
    safe_name = safe_name.replace(' ', '_')
    safe_name = ''.join(c for c in safe_name if c.isalnum() or c in '._-')
    
    # Limit filename length
    if len(safe_name) > 100:
        name_part, ext = safe_name.rsplit('.', 1) if '.' in safe_name else (safe_name, '')
        safe_name = f"{name_part[:95]}.{ext}" if ext else name_part[:100]
    
    return safe_name or "unnamed_file"

def is_rate_limited(identifier, limit=60, window=60):
    """
    Check if an identifier (IP, user, etc.) has exceeded rate limits
    Args:
        identifier (str): Unique identifier to track
        limit (int): Maximum requests allowed in window
        window (int): Time window in seconds
    Returns:
        bool: True if rate limited
    """
    current_time = time.time()
    
    # Clean old entries
    cutoff_time = current_time - window
    requests = rate_limit_storage[identifier]
    
    while requests and requests[0] < cutoff_time:
        requests.popleft()
    
    # Check if limit exceeded
    if len(requests) >= limit:
        return True
    
    # Add current request
    requests.append(current_time)
    return False

def validate_webhook_payload(payload):
    """
    Validate Discord webhook payload structure
    Args:
        payload (dict): Webhook payload to validate
    Returns:
        bool: True if payload structure is valid
    """
    try:
        # Check required fields
        if not isinstance(payload, dict):
            return False
        
        # Validate username length
        username = payload.get('username', '')
        if len(username) > 80:
            return False
        
        # Validate content length
        content = payload.get('content', '')
        if len(content) > 2000:
            return False
        
        # Validate embeds structure if present
        embeds = payload.get('embeds', [])
        if embeds and isinstance(embeds, list):
            for embed in embeds:
                if not isinstance(embed, dict):
                    return False
                # Basic embed field validation
                title = embed.get('title', '')
                description = embed.get('description', '')
                if len(title) > 256 or len(description) > 4096:
                    return False
        
        return True
        
    except Exception as e:
        logging.error(f"Webhook payload validation error: {str(e)}")
        return False

def secure_file_path(base_path, filename):
    """
    Create a secure file path preventing directory traversal
    Args:
        base_path (str): Base directory path
        filename (str): Filename to join
    Returns:
        Path: Secure file path
    """
    base = Path(base_path).resolve()
    safe_name = sanitize_filename(filename)
    file_path = (base / safe_name).resolve()
    
    # Ensure the file path is within the base directory
    if not str(file_path).startswith(str(base)):
        raise SecurityError("Path traversal attempt detected")
    
    return file_path

def log_security_event(event_type, details, ip_address=None):
    """
    Log security-related events
    Args:
        event_type (str): Type of security event
        details (str): Event details
        ip_address (str): Optional IP address (will be hashed)
    """
    hashed_ip = hash_ip_address(ip_address) if ip_address else "unknown"
    
    logging.warning(
        f"SECURITY_EVENT: {event_type} | IP: {hashed_ip} | Details: {details}"
    )

def get_client_ip(request):
    """
    Get client IP address from request, considering proxies
    Args:
        request: Flask request object
    Returns:
        str: Client IP address
    """
    # Check for forwarded headers (common with reverse proxies)
    forwarded_ips = request.headers.get('X-Forwarded-For')
    if forwarded_ips:
        # Take the first IP (client IP)
        return forwarded_ips.split(',')[0].strip()
    
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip.strip()
    
    # Fallback to remote address
    return request.remote_addr

def cleanup_old_files(directory, max_age_hours=24):
    """
    Clean up old files to prevent disk space issues
    Args:
        directory (str): Directory to clean
        max_age_hours (int): Maximum age of files in hours
    """
    try:
        directory_path = Path(directory)
        if not directory_path.exists():
            return
        
        current_time = time.time()
        cutoff_time = current_time - (max_age_hours * 3600)
        
        deleted_count = 0
        for file_path in directory_path.iterdir():
            if file_path.is_file() and file_path.stat().st_mtime < cutoff_time:
                try:
                    file_path.unlink()
                    deleted_count += 1
                except OSError as e:
                    logging.error(f"Failed to delete old file {file_path}: {str(e)}")
        
        if deleted_count > 0:
            logging.info(f"Cleaned up {deleted_count} old files from {directory}")
            
    except Exception as e:
        logging.error(f"Error during file cleanup: {str(e)}")
