"""
Optimized HTTP client for maximum performance
"""

import time
import random
from typing import Optional, Dict, Any
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class HTTPClient:
    """High-performance HTTP client with connection pooling"""
    
    def __init__(self, 
                 timeout: int = 10,
                 user_agent: Optional[str] = None,
                 proxy: Optional[str] = None,
                 delay: float = 0,
                 retries: int = 3,
                 verify_ssl: bool = False):
        
        self.timeout = timeout
        self.delay = delay
        self.retries = retries
        self.verify_ssl = verify_ssl
        
        # Create session with optimized settings
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD"]
        )
        
        # Create adapter with connection pooling
        adapter = HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=retry_strategy,
            pool_block=False
        )
        
        # Mount adapters
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # Set default headers
        default_headers = {
            'User-Agent': user_agent or self._get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        
        self.session.headers.update(default_headers)
        
        # Set proxy if provided
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        # Disable SSL warnings for speed
        requests.packages.urllib3.disable_warnings()
    
    def _get_random_user_agent(self) -> str:
        """Get random user agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0'
        ]
        return random.choice(user_agents)
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Send GET request with optimized settings"""
        return self._request('GET', url, **kwargs)
    
    def post(self, url: str, data: Optional[Dict] = None, **kwargs) -> Optional[requests.Response]:
        """Send POST request with optimized settings"""
        return self._request('POST', url, data=data, **kwargs)
    
    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Send HTTP request with error handling and delay"""
        # Apply delay if configured
        if self.delay > 0:
            time.sleep(self.delay)
        
        # Set default parameters
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', True)
        kwargs.setdefault('verify', self.verify_ssl)
        kwargs.setdefault('stream', False)
        
        try:
            response = self.session.request(method, url, **kwargs)
            if hasattr(response, 'elapsed'):
                response.elapsed = response.elapsed.total_seconds()
            return response
        
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.TooManyRedirects:
            return None
        except requests.exceptions.RequestException as e:
            # Catch all requests-related exceptions
            return None
        except Exception as e:
            # Unexpected error - log if needed
            return None
    
    def close(self):
        """Close the session"""
        self.session.close()
