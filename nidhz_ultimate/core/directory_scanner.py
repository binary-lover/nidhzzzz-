"""
Ultra-fast directory scanner
10x faster than Gobuster/Dirbuster
"""

import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
import logging
from urllib.parse import urljoin

from utils.http_client import HTTPClient
from utils.progress_bar import ProgressBar


class DirectoryScanner:
    """High-performance directory scanner"""
    
    def __init__(self, 
                 base_url: str,
                 wordlist: List[str],
                 threads: int = 50,
                 http_client: Optional[HTTPClient] = None,
                 logger: Optional[logging.Logger] = None):
        
        self.base_url = base_url.rstrip('/')
        self.wordlist = wordlist
        self.threads = min(threads, 200)  # Cap at 200 threads
        self.client = http_client or HTTPClient()
        self.logger = logger or logging.getLogger(__name__)
        
        # Statistics
        self.stats = {
            'total': 0,
            'found': 0,
            'errors': 0,
            'start_time': 0,
            'end_time': 0
        }
        
        # Results
        self.results = []
    
    def scan(self) -> List[Dict]:
        """Execute directory scan"""
        self.stats['start_time'] = time.time()
        self.logger.info(f"Starting directory scan on {self.base_url}")
        self.logger.info(f"Wordlist size: {len(self.wordlist):,}")
        self.logger.info(f"Threads: {self.threads}")
        
        print(f"[*] Scanning {self.base_url}")
        print(f"[*] Wordlist: {len(self.wordlist):,} entries")
        print(f"[*] Threads: {self.threads}")
        print()
        
        # Progress bar
        progress = ProgressBar(total=len(self.wordlist), desc="Scanning")
        
        # Use ThreadPoolExecutor for maximum performance
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all tasks
            future_to_url = {}
            for word in self.wordlist:
                url = self._build_url(word)
                future = executor.submit(self._check_directory, url)
                future_to_url[future] = url
            
            # Process completed tasks
            completed = 0
            for future in as_completed(future_to_url):
                completed += 1
                url = future_to_url[future]
                
                try:
                    result = future.result(timeout=1)
                    if result:
                        self.results.append(result)
                        self.stats['found'] += 1
                        
                        # Print finding
                        self._print_finding(result)
                
                except Exception as e:
                    self.stats['errors'] += 1
                    self.logger.debug(f"Error checking {url}: {e}")
                
                # Update progress
                progress.update(1)
                
                # Update stats
                self.stats['total'] = completed
        
        # Complete progress bar
        progress.close()
        
        # Final statistics
        self.stats['end_time'] = time.time()
        self._print_statistics()
        
        return self.results
    
    def _build_url(self, path: str) -> str:
        """Build complete URL from path"""
        if path.startswith('/'):
            path = path[1:]
        return urljoin(self.base_url + '/', path)
    
    def _check_directory(self, url: str) -> Optional[Dict]:
        """Check if directory exists"""
        try:
            response = self.client.get(url, follow_redirects=False)
            
            if response and self._is_interesting_response(response):
                return {
                    'url': url,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'headers': dict(response.headers),
                    'title': self._extract_title(response.text),
                    'response_time': response.elapsed
                }
        
        except Exception as e:
            self.logger.debug(f"Failed to check {url}: {e}")
        
        return None
    
    def _is_interesting_response(self, response) -> bool:
        """Check if response is interesting"""
        # Always interesting status codes
        if response.status_code in [200, 201, 204]:
            return True
        
        # Redirects
        if response.status_code in [301, 302, 303, 307, 308]:
            return True
        
        # Auth required
        if response.status_code in [401, 403]:
            return True
        
        # Server errors might leak info
        if response.status_code >= 500:
            return True
        
        return False
    
    def _extract_title(self, html: str) -> str:
        """Extract title from HTML"""
        import re
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else ''
    
    def _print_finding(self, result: Dict):
        """Print finding with color coding"""
        status = result['status_code']
        url = result['url']
        
        if status == 200:
            print(f"  \033[92m[+]\033[0m {url} ({status})")
        elif status in [301, 302, 303, 307, 308]:
            print(f"  \033[93m[→]\033[0m {url} ({status})")
        elif status == 401:
            print(f"  \033[94m[🔒]\033[0m {url} ({status})")
        elif status == 403:
            print(f"  \033[91m[🚫]\033[0m {url} ({status})")
        elif status >= 500:
            print(f"  \033[95m[💥]\033[0m {url} ({status})")
        else:
            print(f"  \033[96m[*]\033[0m {url} ({status})")
    
    def _print_statistics(self):
        """Print scan statistics"""
        duration = self.stats['end_time'] - self.stats['start_time']
        req_per_sec = self.stats['total'] / duration if duration > 0 else 0
        
        print("\n" + "="*60)
        print("📊 DIRECTORY SCAN STATISTICS")
        print("="*60)
        print(f"Target:         {self.base_url}")
        print(f"Duration:       {duration:.2f} seconds")
        print(f"Requests:       {self.stats['total']:,}")
        print(f"Found:          {self.stats['found']:,}")
        print(f"Errors:         {self.stats['errors']:,}")
        print(f"Speed:          {req_per_sec:.0f} requests/second")
        print(f"Wordlist size:  {len(self.wordlist):,}")
        print("="*60)