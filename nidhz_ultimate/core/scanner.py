"""
Main scanner class for NIDHZ
"""

import time
import random
from typing import List, Dict, Optional
from enum import Enum
from dataclasses import dataclass, asdict
import json
import logging

from .directory_scanner import DirectoryScanner
from .xss_scanner import XSSScanner
from .sqli_scanner import SQLiScanner
from .technology_detector import TechnologyDetector
from .reporter import Reporter
from utils.wordlist_manager import WordlistManager
from utils.http_client import HTTPClient
from utils.progress_bar import ProgressBar


class ScanMode(Enum):
    QUICK = "quick"
    NORMAL = "normal"
    DEEP = "deep"
    AGGRESSIVE = "aggressive"


@dataclass
class ScanConfig:
    """Scan configuration"""
    target: str
    mode: ScanMode
    threads: int
    timeout: int
    user_agent: Optional[str]
    proxy: Optional[str]
    delay: float
    retries: int
    skip_vuln: bool


@dataclass
class ScanResult:
    """Scan result container"""
    target: str
    start_time: float
    end_time: float
    technology: List[str]
    directories: List[Dict]
    xss_vulnerabilities: List[Dict]
    sqli_vulnerabilities: List[Dict]
    statistics: Dict


class NidhzScanner:
    """Main NIDHZ scanner"""
    
    def __init__(self, 
                 target: str,
                 mode: str = "normal",
                 threads: int = 50,
                 output_dir: str = "results",
                 timeout: int = 10,
                 user_agent: Optional[str] = None,
                 proxy: Optional[str] = None,
                 delay: float = 0,
                 retries: int = 3,
                 skip_vuln: bool = False,
                 logger: Optional[logging.Logger] = None):
        
        self.config = ScanConfig(
            target=target.rstrip('/'),
            mode=ScanMode(mode),
            threads=threads,
            timeout=timeout,
            user_agent=user_agent,
            proxy=proxy,
            delay=delay,
            retries=retries,
            skip_vuln=skip_vuln
        )
        
        self.output_dir = output_dir
        self.logger = logger or logging.getLogger(__name__)
        
        # Results storage
        self.results = ScanResult(
            target=target,
            start_time=0,
            end_time=0,
            technology=[],
            directories=[],
            xss_vulnerabilities=[],
            sqli_vulnerabilities=[],
            statistics={}
        )
        
        # Initialize components
        self.http_client = HTTPClient(
            timeout=timeout,
            user_agent=user_agent,
            proxy=proxy,
            delay=delay,
            retries=retries
        )
        
        self.wordlist_manager = WordlistManager()
        self.tech_detector = TechnologyDetector(self.http_client)
        self.reporter = Reporter(output_dir)
        
    def run(self):
        """Execute complete scan"""
        self.results.start_time = time.time()
        
        try:
            # Step 1: Technology Detection
            self._detect_technology()
            
            # Step 2: Directory Discovery
            directories = self._scan_directories()
            self.results.directories = directories
            
            # Step 3: Vulnerability Scanning
            if not self.config.skip_vuln:
                self._scan_vulnerabilities(directories)
            
            # Step 4: Generate Reports
            self._generate_reports()
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            raise
        
        finally:
            self.results.end_time = time.time()
            self._print_summary()
    
    def _detect_technology(self):
        """Detect technology stack"""
        self.logger.info("Detecting technology stack...")
        
        try:
            response = self.http_client.get(self.config.target)
            if response:
                tech = self.tech_detector.detect(response)
                self.results.technology = tech
                
                if tech:
                    print(f"[+] Detected: {', '.join(tech)}")
                else:
                    print("[*] No specific technology detected")
        
        except Exception as e:
            self.logger.warning(f"Technology detection failed: {e}")
            print("[!] Technology detection failed")
    
    def _scan_directories(self) -> List[Dict]:
        """Scan for directories"""
        self.logger.info("Starting directory discovery...")
        
        # Select wordlist based on mode
        wordlist = self._get_wordlist_for_mode()
        
        # Add technology-specific paths
        tech_wordlists = self._get_tech_specific_wordlists()
        wordlist.extend(tech_wordlists)
        
        # Remove duplicates and shuffle
        wordlist = list(set(wordlist))
        random.shuffle(wordlist)
        
        # Create and run directory scanner
        scanner = DirectoryScanner(
            base_url=self.config.target,
            wordlist=wordlist,
            threads=self.config.threads,
            http_client=self.http_client,
            logger=self.logger
        )
        
        return scanner.scan()
    
    def _scan_vulnerabilities(self, directories: List[Dict]):
        """Scan for vulnerabilities"""
        self.logger.info("Starting vulnerability scanning...")
        
        urls_to_scan = [self.config.target]
        if directories:
            urls_to_scan.extend([d['url'] for d in directories[:10]])  # Top 10
        
        # XSS Scanning
        xss_scanner = XSSScanner(self.http_client, self.logger)
        for url in urls_to_scan:
            xss_vulns = xss_scanner.scan(url)
            self.results.xss_vulnerabilities.extend(xss_vulns)
        
        # SQLi Scanning
        sqli_scanner = SQLiScanner(self.http_client, self.logger)
        for url in urls_to_scan:
            sqli_vulns = sqli_scanner.scan(url)
            self.results.sqli_vulnerabilities.extend(sqli_vulns)
    
    def _get_wordlist_for_mode(self) -> List[str]:
        """Get appropriate wordlist for scan mode"""
        if self.config.mode == ScanMode.QUICK:
            return self.wordlist_manager.get_quick_wordlist()
        elif self.config.mode == ScanMode.NORMAL:
            return self.wordlist_manager.get_common_wordlist()
        elif self.config.mode == ScanMode.DEEP:
            return self.wordlist_manager.get_big_wordlist()
        else:  # AGGRESSIVE
            return self.wordlist_manager.get_massive_wordlist()
    
    def _get_tech_specific_wordlists(self) -> List[str]:
        """Get technology-specific wordlists"""
        wordlists = []
        
        if 'WordPress' in self.results.technology:
            wordlists.extend(self.wordlist_manager.get_wordpress_wordlist())
        if 'Joomla' in self.results.technology:
            wordlists.extend(self.wordlist_manager.get_joomla_wordlist())
        if 'Drupal' in self.results.technology:
            wordlists.extend(self.wordlist_manager.get_drupal_wordlist())
        if 'Laravel' in self.results.technology:
            wordlists.extend(self.wordlist_manager.get_laravel_wordlist())
        
        return wordlists
    
    def _generate_reports(self):
        """Generate all report formats"""
        self.logger.info("Generating reports...")
        
        # Convert results to dictionary
        results_dict = asdict(self.results)
        
        # Add scan configuration
        results_dict['config'] = {
            'mode': self.config.mode.value,
            'threads': self.config.threads,
            'timeout': self.config.timeout,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Generate reports
        self.reporter.generate_html_report(results_dict)
        self.reporter.generate_json_report(results_dict)
        self.reporter.generate_csv_report(results_dict)
        self.reporter.generate_markdown_report(results_dict)
        
        print(f"[+] Reports saved to: {self.output_dir}/")
    
    def _print_summary(self):
        """Print scan summary"""
        duration = self.results.end_time - self.results.start_time
        minutes, seconds = divmod(duration, 60)
        
        print("\n" + "="*60)
        print("📊 SCAN SUMMARY")
        print("="*60)
        print(f"Target:          {self.config.target}")
        print(f"Mode:            {self.config.mode.value}")
        print(f"Duration:        {int(minutes)}m {int(seconds)}s")
        print(f"Directories:     {len(self.results.directories)} found")
        print(f"XSS Vulns:       {len(self.results.xss_vulnerabilities)}")
        print(f"SQLi Vulns:      {len(self.results.sqli_vulnerabilities)}")
        print(f"Technology:      {', '.join(self.results.technology) or 'None'}")
        print(f"Reports:         {self.output_dir}/")
        print("="*60)
        
        # Show critical findings
        if self.results.xss_vulnerabilities or self.results.sqli_vulnerabilities:
            print("\n⚠️  CRITICAL FINDINGS:")
            
            for vuln in self.results.xss_vulnerabilities:
                if vuln.get('confidence') == 'High':
                    print(f"  • XSS at: {vuln.get('url', 'N/A')}")
            
            for vuln in self.results.sqli_vulnerabilities:
                if vuln.get('confidence') == 'High':
                    print(f"  • SQLi at: {vuln.get('url', 'N/A')}")
        
        print("\n✅ Scan completed successfully!")