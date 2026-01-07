"""
Utility functions for NIDHZ
"""

import os
import sys
import logging
import hashlib
from datetime import datetime
from typing import Optional
import re
from urllib.parse import urlparse


def setup_logging(output_dir: str, verbose: bool = False) -> logging.Logger:
    """Setup logging configuration"""
    log_file = os.path.join(output_dir, 'scan.log')
    
    # Create logger
    logger = logging.getLogger('nidhz')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # File handler
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO if verbose else logging.WARNING)
    console_format = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    return logger


def validate_url(url: str) -> str:
    """Validate and normalize URL"""
    if not url:
        raise ValueError("URL cannot be empty")
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Parse URL
    parsed = urlparse(url)
    
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    
    # Normalize
    normalized = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
        path=parsed.path.rstrip('/') if parsed.path != '/' else '/'
    ).geturl()
    
    return normalized


def print_banner():
    """Print NIDHZ banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║  ███╗   ██╗██╗██████╗ ██╗  ██╗███████╗    ██╗   ██╗██╗           ║
║  ████╗  ██║██║██╔══██╗██║  ██║╚════██║    ██║   ██║██║           ║
║  ██╔██╗ ██║██║██║  ██║███████║   ██╔╝    ██║   ██║██║           ║
║  ██║╚██╗██║██║██║  ██║██╔══██║  ██╔╝     ██║   ██║██║           ║
║  ██║ ╚████║██║██████╔╝██║  ██║███████╗██╗╚██████╔╝███████╗██╗   ║
║  ╚═╝  ╚═══╝╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚══════╝╚═╝   ║
║                                                                   ║
║                    U L T I M A T E   v 2 . 0                      ║
║               Fastest Web Vulnerability Scanner                   ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """
    
    print("\033[95m" + banner + "\033[0m")
    print("                 \033[93mby Security Researcher\033[0m")
    print("=" * 65)
    print()


def calculate_hash(data: str, algorithm: str = 'sha256') -> str:
    """Calculate hash of data"""
    hash_func = getattr(hashlib, algorithm, hashlib.sha256)
    return hash_func(data.encode()).hexdigest()


def format_bytes(size: int) -> str:
    """Format bytes to human readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def format_time(seconds: float) -> str:
    """Format seconds to human readable time"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h"
    else:
        days = seconds / 86400
        return f"{days:.1f}d"


def get_timestamp() -> str:
    """Get current timestamp"""
    return datetime.now().strftime('%Y%m%d_%H%M%S')


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file system use"""
    # Remove invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove multiple underscores
    filename = re.sub(r'_+', '_', filename)
    # Trim
    filename = filename.strip('._ ')
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255 - len(ext)] + ext
    return filename


def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    parsed = urlparse(url)
    return parsed.netloc


def is_valid_ip(address: str) -> bool:
    """Check if string is a valid IP address"""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, address):
        parts = address.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            return True
    return False


def colorize(text: str, color: str) -> str:
    """Colorize text for terminal output"""
    colors = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'reset': '\033[0m'
    }
    return colors.get(color, '') + text + colors.get('reset', '')


def print_progress(iteration: int, total: int, prefix: str = '', suffix: str = ''):
    """Print progress bar"""
    bar_length = 50
    filled_length = int(bar_length * iteration // total)
    bar = '█' * filled_length + '░' * (bar_length - filled_length)
    percent = 100 * iteration / total
    
    sys.stdout.write(f'\r{prefix} |{bar}| {percent:.1f}% {suffix}')
    sys.stdout.flush()
    
    if iteration == total:
        print()