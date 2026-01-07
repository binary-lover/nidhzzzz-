#!/usr/bin/env python3
"""
Quick scan example for NIDHZ
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import NidhzScanner


def main():
    """Run quick scan example"""
    print("🚀 NIDHZ Quick Scan Example")
    print("=" * 50)
    
    # Target URL (use a test server or local demo)
    target = "http://testphp.vulnweb.com"
    
    # Create scanner
    scanner = NidhzScanner(
        target=target,
        mode="quick",
        threads=20,
        output_dir="quick_scan_results",
        timeout=5,
        skip_vuln=False  # Set to True to skip vulnerability scanning
    )
    
    print(f"Target: {target}")
    print(f"Mode: Quick")
    print(f"Threads: 20")
    print()
    
    # Run scan
    try:
        scanner.run()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")


if __name__ == "__main__":
    main()