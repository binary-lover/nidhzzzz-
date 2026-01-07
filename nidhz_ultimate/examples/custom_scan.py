#!/usr/bin/env python3
"""
Custom scan configuration example for NIDHZ
"""

import sys
import os
import argparse
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import NidhzScanner
from core.directory_scanner import DirectoryScanner
from core.xss_scanner import XSSScanner
from core.sqli_scanner import SQLiScanner
from utils.http_client import HTTPClient
from utils.wordlist_manager import WordlistManager


def custom_directory_scan():
    """Custom directory scanning example"""
    print("📁 Custom Directory Scan")
    print("=" * 50)
    
    target = input("Enter target URL: ").strip()
    if not target:
        print("[!] No target provided")
        return
    
    # Create custom wordlist
    wordlist_manager = WordlistManager()
    
    # Mix and match wordlists
    quick = wordlist_manager.get_quick_wordlist()
    wp = wordlist_manager.get_wordpress_wordlist()
    
    custom_wordlist = quick + wp
    print(f"Custom wordlist size: {len(custom_wordlist)}")
    
    # Create HTTP client with custom settings
    http_client = HTTPClient(
        timeout=10,
        user_agent="NIDHZ-Custom-Scanner/1.0",
        delay=0.2,  # Delay to avoid rate limiting
        retries=2
    )
    
    # Run custom scan
    scanner = DirectoryScanner(
        base_url=target,
        wordlist=custom_wordlist,
        threads=30,
        http_client=http_client
    )
    
    try:
        results = scanner.scan()
        print(f"\n✅ Found {len(results)} directories")
        
        # Save results
        with open('custom_scan_results.txt', 'w') as f:
            for result in results:
                f.write(f"{result['url']}\n")
        
        print("Results saved to custom_scan_results.txt")
        
    except Exception as e:
        print(f"[!] Error: {e}")


def custom_vulnerability_scan():
    """Custom vulnerability scanning example"""
    print("🎯 Custom Vulnerability Scan")
    print("=" * 50)
    
    target = input("Enter target URL: ").strip()
    if not target:
        print("[!] No target provided")
        return
    
    # Create HTTP client
    http_client = HTTPClient(timeout=10)
    
    # Choose scan type
    print("\nSelect scan type:")
    print("1. XSS Scan only")
    print("2. SQLi Scan only")
    print("3. Both XSS and SQLi")
    
    choice = input("Enter choice (1-3): ").strip()
    
    if choice == '1':
        # XSS scan only
        scanner = XSSScanner(http_client)
        vulnerabilities = scanner.scan(target)
        print(f"\nFound {len(vulnerabilities)} XSS vulnerabilities")
        
    elif choice == '2':
        # SQLi scan only
        scanner = SQLiScanner(http_client)
        vulnerabilities = scanner.scan(target)
        print(f"\nFound {len(vulnerabilities)} SQLi vulnerabilities")
        
    elif choice == '3':
        # Both scans
        xss_scanner = XSSScanner(http_client)
        sqli_scanner = SQLiScanner(http_client)
        
        xss_vulns = xss_scanner.scan(target)
        sqli_vulns = sqli_scanner.scan(target)
        
        print(f"\nFound {len(xss_vulns)} XSS vulnerabilities")
        print(f"Found {len(sqli_vulns)} SQLi vulnerabilities")
        
    else:
        print("[!] Invalid choice")


def batch_scan():
    """Batch scan multiple targets"""
    print("📋 Batch Scan Multiple Targets")
    print("=" * 50)
    
    # Read targets from file or input
    targets_file = input("Enter path to targets file (or press Enter for manual input): ").strip()
    
    targets = []
    
    if targets_file and os.path.exists(targets_file):
        with open(targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        print("Enter targets (one per line, empty line to finish):")
        while True:
            target = input().strip()
            if not target:
                break
            targets.append(target)
    
    if not targets:
        print("[!] No targets provided")
        return
    
    print(f"\nScanning {len(targets)} targets...")
    
    for i, target in enumerate(targets, 1):
        print(f"\n[{i}/{len(targets)}] Scanning: {target}")
        
        try:
            scanner = NidhzScanner(
                target=target,
                mode="quick",
                threads=20,
                output_dir=f"batch_scan/{target.replace('://', '_').replace('/', '_')}",
                timeout=10,
                skip_vuln=True  # Skip vuln for speed
            )
            
            scanner.run()
            
        except Exception as e:
            print(f"[!] Error scanning {target}: {e}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="NIDHZ Custom Scan Examples")
    parser.add_argument('--type', choices=['dir', 'vuln', 'batch', 'all'],
                       default='all', help='Scan type')
    
    args = parser.parse_args()
    
    print("🚀 NIDHZ Custom Scan Examples")
    print("=" * 50)
    
    if args.type == 'dir' or args.type == 'all':
        custom_directory_scan()
    
    if args.type == 'vuln' or args.type == 'all':
        custom_vulnerability_scan()
    
    if args.type == 'batch' or args.type == 'all':
        batch_scan()


if __name__ == "__main__":
    main()