#!/usr/bin/env python3
"""
Configuration file for R4VEN
Contains security settings and application configuration
"""

import os
from pathlib import Path

# Application Settings
APP_NAME = "R4VEN"
VERSION = "1.2.0"
DEBUG = False

# Server Configuration
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8000
DEFAULT_TARGET_URL = "http://localhost:8000/image"

# File Upload Security
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp'}
UPLOAD_FOLDER = 'snapshots'

# Logging Configuration
LOG_FILE = "r4ven.log"
LOG_LEVEL = "INFO"
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'

# Security Headers
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
}

# Rate Limiting (requests per minute)
RATE_LIMIT = 60

# Session Configuration
SESSION_TIMEOUT = 3600  # 1 hour in seconds

# File Names
HTML_FILE_NAME = "index.html"
DISCORD_WEBHOOK_FILE_NAME = "dwebhook.js"

# Directory Setup
def ensure_directories():
    """Create necessary directories if they don't exist."""
    directories = [UPLOAD_FOLDER]
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)

# Security Validation
def validate_webhook_url(url):
    """Validate Discord webhook URL format."""
    import re
    webhook_pattern = re.compile(
        r'^https://(discord(app)?\.com)/api(/v\d+)?/webhooks/\d+/[A-Za-z0-9_-]+/?$'
    )
    return bool(webhook_pattern.match(url))

def validate_file_extension(filename):
    """Validate file extension against allowed types."""
    if not filename or '.' not in filename:
        return False
    extension = filename.rsplit('.', 1)[1].lower()
    return extension in ALLOWED_EXTENSIONS

# Environment Configuration
def load_from_env():
    """Load configuration from environment variables."""
    global DEFAULT_PORT, DEBUG, LOG_LEVEL
    
    # Override with environment variables if set
    DEFAULT_PORT = int(os.getenv('R4VEN_PORT', DEFAULT_PORT))
    DEBUG = os.getenv('R4VEN_DEBUG', 'False').lower() == 'true'
    LOG_LEVEL = os.getenv('R4VEN_LOG_LEVEL', LOG_LEVEL)

# Initialize configuration
load_from_env()
ensure_directories()
