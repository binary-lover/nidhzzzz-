#!/usr/bin/env python3
"""
NIDHZ ULTIMATE - Fastest Web Vulnerability Scanner
Version: 2.0
Author: Security Researcher
License: MIT
"""

import sys
import os
import argparse
import time
from datetime import datetime
from core.scanner import NidhzScanner
from utils.helpers import setup_logging, validate_url, print_banner

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='NIDHZ ULTIMATE - Fastest Web Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  nidhz.py https://example.com                    # Quick scan
  nidhz.py https://example.com -m deep -t 100    # Deep scan with 100 threads
  nidhz.py https://example.com -o results/       # Save to custom directory
  nidhz.py https://example.com --no-vuln         # Skip vulnerability scanning
        """
    )
    
    parser.add_argument('target', nargs='?', help='Target URL to scan')
    parser.add_argument('-m', '--mode', 
                       choices=['quick', 'normal', 'deep', 'aggressive'],
                       default='normal', 
                       help='Scan mode (default: normal)')
    parser.add_argument('-t', '--threads', 
                       type=int, 
                       default=50,
                       help='Number of threads (default: 50)')
    parser.add_argument('-o', '--output', 
                       help='Output directory')
    parser.add_argument('--no-vuln', 
                       action='store_true',
                       help='Skip vulnerability scanning')
    parser.add_argument('--timeout', 
                       type=int, 
                       default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--user-agent', 
                       help='Custom User-Agent')
    parser.add_argument('--proxy', 
                       help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--delay', 
                       type=float, 
                       default=0,
                       help='Delay between requests in seconds')
    parser.add_argument('--retries', 
                       type=int, 
                       default=3,
                       help='Number of retries for failed requests')
    parser.add_argument('-v', '--verbose', 
                       action='store_true',
                       help='Verbose output')
    parser.add_argument('--version', 
                       action='store_true',
                       help='Show version')
    
    args = parser.parse_args()
    
    # Show version
    if args.version:
        print("NIDHZ Ultimate v2.0")
        return
    
    # Check if target is provided
    if not args.target:
        print("[!] Error: target URL is required")
        parser.print_help()
        sys.exit(1)
    
    # Validate and normalize URL
    try:
        target = validate_url(args.target)
    except ValueError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
    
    # Create output directory
    if args.output:
        output_dir = args.output
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = f"nidhz_scan_{timestamp}"
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Setup logging
    logger = setup_logging(output_dir, args.verbose)
    
    # Print banner
    print_banner()
    
    # Create scanner instance
    scanner = NidhzScanner(
        target=target,
        mode=args.mode,
        threads=args.threads,
        output_dir=output_dir,
        timeout=args.timeout,
        user_agent=args.user_agent,
        proxy=args.proxy,
        delay=args.delay,
        retries=args.retries,
        skip_vuln=args.no_vuln,
        logger=logger
    )
    
    # Run scan
    try:
        scanner.run()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        logger.warning("Scan interrupted by user")
        
        # Save partial results
        if hasattr(scanner, 'results'):
            scanner.generate_reports(partial=True)
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")
        logger.error(f"Scan failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
