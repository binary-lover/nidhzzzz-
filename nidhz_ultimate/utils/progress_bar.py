"""
Custom progress bar for NIDHZ
"""

import sys
import time
from typing import Optional
from datetime import datetime, timedelta


class ProgressBar:
    """Custom progress bar with ETA and statistics"""
    
    def __init__(self, total: int, desc: str = "Processing", width: int = 50):
        self.total = total
        self.desc = desc
        self.width = width
        self.start_time = time.time()
        self.current = 0
        self.last_print_len = 0
    
    def update(self, n: int = 1):
        """Update progress"""
        self.current += n
        self._print()
    
    def _print(self):
        """Print progress bar"""
        percent = self.current / self.total
        filled = int(self.width * percent)
        bar = '█' * filled + '░' * (self.width - filled)
        
        # Calculate ETA
        elapsed = time.time() - self.start_time
        if self.current > 0:
            items_per_second = self.current / elapsed
            eta_seconds = (self.total - self.current) / items_per_second if items_per_second > 0 else 0
            eta_str = str(timedelta(seconds=int(eta_seconds)))
        else:
            items_per_second = 0
            eta_str = "??:??:??"
        
        # Format stats
        stats = f"{self.current}/{self.total} [{elapsed:.1f}s<{eta_str}, {items_per_second:.1f}it/s]"
        
        # Create output
        output = f"\r{self.desc}: |{bar}| {percent:.1%} {stats}"
        
        # Clear previous output
        sys.stdout.write(' ' * self.last_print_len)
        sys.stdout.write('\r')
        
        # Print new output
        sys.stdout.write(output)
        sys.stdout.flush()
        
        self.last_print_len = len(output)
    
    def close(self):
        """Close progress bar"""
        self._print()
        print()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class MultiProgressBar:
    """Multiple progress bars for different tasks"""
    
    def __init__(self):
        self.bars = {}
        self.lock = False
    
    def add_bar(self, name: str, total: int, desc: str = ""):
        """Add a progress bar"""
        self.bars[name] = {
            'bar': ProgressBar(total, desc),
            'total': total,
            'current': 0
        }
    
    def update(self, name: str, n: int = 1):
        """Update a specific progress bar"""
        if name in self.bars:
            self.bars[name]['bar'].update(n)
            self.bars[name]['current'] += n
    
    def close_all(self):
        """Close all progress bars"""
        for bar_info in self.bars.values():
            bar_info['bar'].close()
    
    def get_status(self, name: str) -> dict:
        """Get status of a progress bar"""
        if name in self.bars:
            bar_info = self.bars[name]
            percent = bar_info['current'] / bar_info['total'] * 100
            return {
                'current': bar_info['current'],
                'total': bar_info['total'],
                'percent': percent,
                'description': bar_info['bar'].desc
            }
        return {}