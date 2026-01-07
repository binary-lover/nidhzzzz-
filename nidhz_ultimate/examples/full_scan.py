#!/usr/bin/env python3
"""
Full scan example for NIDHZ
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import NidhzScanner


def main():
    """Run full scan example"""
    print("🚀 NIDHZ Full Scan Example")
    print("=" * 50)
    
    # Get target from user or use default
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target URL: ").strip()
    
    if not target:
        print("[!] No target provided")
        return
    
    # Create scanner with full configuration
    scanner = NidhzScanner(
        target=target,
        mode="deep",  # Use deep mode for comprehensive scan
        threads=100,  # Maximum threads
        output_dir="full_scan_results",
        timeout=15,
        delay=0.1,  # Small delay between requests
        retries=2,
        skip_vuln=False
    )
    
    print(f"Target: {target}")
    print(f"Mode: Deep (comprehensive)")
    print(f"Threads: 100")
    print(f"Delay: 0.1s between requests")
    print()
    
    # Confirm scan
    confirm = input("This is a comprehensive scan that may take time. Continue? (y/n): ")
    if confirm.lower() != 'y':
        print("[*] Scan cancelled")
        return
    
    # Run scan
    try:
        scanner.run()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")


if __name__ == "__main__":
    main()