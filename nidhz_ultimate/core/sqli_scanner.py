"""
Advanced SQL injection scanner
"""

import re
import time
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode
import logging

from utils.http_client import HTTPClient
from utils.wordlist_manager import WordlistManager


class SQLiScanner:
    """Advanced SQL injection scanner with multiple detection methods"""
    
    def __init__(self, 
                 http_client: HTTPClient,
                 logger: Optional[logging.Logger] = None):
        
        self.client = http_client
        self.logger = logger or logging.getLogger(__name__)
        self.wordlist_manager = WordlistManager()
        
        # Load payloads
        self.error_payloads = self.wordlist_manager.get_sqli_error_payloads()
        self.time_payloads = self.wordlist_manager.get_sqli_time_payloads()
        self.boolean_payloads = self.wordlist_manager.get_sqli_boolean_payloads()
        
        # SQL error patterns
        self.sql_error_patterns = {
            'mysql': [
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_.*',
                r'MySqlClient\.',
                r'mysql_fetch',
                r'You have an error in your SQL syntax',
                r'MySQL server version',
                r'MariaDB server version',
                r'got an error in conversation'
            ],
            'mssql': [
                r'Microsoft OLE DB Provider for SQL Server',
                r'ODBC SQL Server Driver',
                r'SQL Server.*Driver',
                r'SQLServer JDBC Driver',
                r'Incorrect syntax near',
                r'Unclosed quotation mark',
                r"'[^']*' expected",
                r'Procedure or function'
            ],
            'postgres': [
                r'PostgreSQL.*ERROR',
                r'Warning.*pg_.*',
                r'valid PostgreSQL result',
                r'Npgsql\.',
                r'PG::SyntaxError',
                r'PostgreSQL query failed',
                r'relation.*does not exist'
            ],
            'oracle': [
                r'ORA-\d{5}',
                r'Oracle error',
                r'Oracle.*Driver',
                r'Warning.*oci_.*',
                r'ORA-',
                r'PLS-',
                r'SQL command not properly ended'
            ],
            'sqlite': [
                r'SQLite/JDBCDriver',
                r'SQLite\.Exception',
                r'System\.Data\.SQLite',
                r'SQLite error',
                r'no such table',
                r'no such column'
            ]
        }
    
    def scan(self, url: str) -> List[Dict]:
        """Scan URL for SQL injection vulnerabilities"""
        self.logger.info(f"Scanning for SQLi: {url}")
        
        vulnerabilities = []
        
        # Get baseline response
        try:
            baseline = self.client.get(url)
            if not baseline:
                return vulnerabilities
            
            # Test URL parameters
            error_vulns = self._test_error_based(url, baseline)
            vulnerabilities.extend(error_vulns)
            
            if not error_vulns:  # Only test other types if no errors found
                time_vulns = self._test_time_based(url, baseline)
                vulnerabilities.extend(time_vulns)
                
                boolean_vulns = self._test_boolean_based(url, baseline)
                vulnerabilities.extend(boolean_vulns)
            
        except Exception as e:
            self.logger.error(f"SQLi scan failed for {url}: {e}")
        
        return vulnerabilities
    
    def _test_error_based(self, url: str, baseline) -> List[Dict]:
        """Test for error-based SQL injection"""
        vulnerabilities = []
        parsed = urlparse(url)
        
        if not parsed.query:
            return vulnerabilities
        
        params = parse_qs(parsed.query)
        
        for param_name in params:
            self.logger.debug(f"Testing error-based SQLi on: {param_name}")
            
            # Test error payloads
            for payload in self.error_payloads[:15]:  # Limit to 15 payloads
                # Build test URL
                test_params = params.copy()
                test_params[param_name] = payload
                
                test_url = parsed._replace(
                    query=urlencode(test_params, doseq=True)
                ).geturl()
                
                # Send request
                try:
                    response = self.client.get(test_url)
                    if response:
                        # Check for SQL errors
                        db_type, error_msg = self._detect_sql_error(response.text)
                        
                        if db_type:
                            confidence = self._calculate_error_confidence(error_msg)
                            
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'subtype': 'Error-Based',
                                'database': db_type,
                                'url': test_url,
                                'parameter': param_name,
                                'payload': payload,
                                'confidence': confidence,
                                'evidence': error_msg[:500]
                            })
                            
                            self.logger.info(f"Found error-based SQLi ({db_type}) in {param_name}")
                            break  # Stop after first finding
                
                except Exception as e:
                    self.logger.debug(f"Error testing {param_name}: {e}")
        
        return vulnerabilities
    
    def _test_time_based(self, url: str, baseline) -> List[Dict]:
        """Test for time-based blind SQL injection"""
        vulnerabilities = []
        parsed = urlparse(url)
        
        if not parsed.query:
            return vulnerabilities
        
        params = parse_qs(parsed.query)
        baseline_time = baseline.elapsed.total_seconds()
        
        for param_name in params:
            self.logger.debug(f"Testing time-based SQLi on: {param_name}")
            
            # Test time payloads
            for payload in self.time_payloads[:10]:  # Limit to 10 payloads
                # Build test URL
                test_params = params.copy()
                test_params[param_name] = payload
                
                test_url = parsed._replace(
                    query=urlencode(test_params, doseq=True)
                ).geturl()
                
                # Measure response time
                try:
                    start_time = time.time()
                    response = self.client.get(test_url)
                    end_time = time.time()
                    
                    if response:
                        response_time = end_time - start_time
                        
                        # Check for significant delay
                        if response_time > baseline_time + 5:  # 5 second delay
                            confidence = self._calculate_time_confidence(response_time, baseline_time)
                            
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'subtype': 'Time-Based Blind',
                                'url': test_url,
                                'parameter': param_name,
                                'payload': payload,
                                'baseline_time': f"{baseline_time:.2f}s",
                                'response_time': f"{response_time:.2f}s",
                                'delay': f"{response_time - baseline_time:.2f}s",
                                'confidence': confidence
                            })
                            
                            self.logger.info(f"Found time-based SQLi in {param_name}")
                            break
                
                except Exception as e:
                    self.logger.debug(f"Time test failed for {param_name}: {e}")
        
        return vulnerabilities
    
    def _test_boolean_based(self, url: str, baseline) -> List[Dict]:
        """Test for boolean-based blind SQL injection"""
        vulnerabilities = []
        parsed = urlparse(url)
        
        if not parsed.query:
            return vulnerabilities
        
        params = parse_qs(parsed.query)
        baseline_content = baseline.text
        baseline_length = len(baseline_content)
        
        for param_name in params:
            self.logger.debug(f"Testing boolean-based SQLi on: {param_name}")
            
            # Test true condition
            true_payload = "' AND '1'='1' -- "
            false_payload = "' AND '1'='2' -- "
            
            true_url = self._build_test_url(parsed, params, param_name, true_payload)
            false_url = self._build_test_url(parsed, params, param_name, false_payload)
            
            try:
                # Get true condition response
                true_response = self.client.get(true_url)
                if not true_response:
                    continue
                
                # Get false condition response
                false_response = self.client.get(false_url)
                if not false_response:
                    continue
                
                # Compare responses
                if self._responses_differ_significantly(true_response, false_response, baseline):
                    confidence = 'High'
                    
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'subtype': 'Boolean-Based Blind',
                        'url': true_url,
                        'parameter': param_name,
                        'true_payload': true_payload,
                        'false_payload': false_payload,
                        'true_length': len(true_response.text),
                        'false_length': len(false_response.text),
                        'difference': abs(len(true_response.text) - len(false_response.text)),
                        'confidence': confidence
                    })
                    
                    self.logger.info(f"Found boolean-based SQLi in {param_name}")
            
            except Exception as e:
                self.logger.debug(f"Boolean test failed for {param_name}: {e}")
        
        return vulnerabilities
    
    def _build_test_url(self, parsed, params, param_name, payload):
        """Build test URL with payload"""
        test_params = params.copy()
        test_params[param_name] = payload
        
        return parsed._replace(
            query=urlencode(test_params, doseq=True)
        ).geturl()
    
    def _detect_sql_error(self, text: str):
        """Detect SQL error in response text"""
        text_lower = text.lower()
        
        for db_type, patterns in self.sql_error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    # Extract error message
                    match = re.search(pattern, text, re.IGNORECASE)
                    error_msg = match.group() if match else "SQL error detected"
                    return db_type, error_msg
        
        return None, None
    
    def _responses_differ_significantly(self, resp1, resp2, baseline) -> bool:
        """Check if responses differ significantly"""
        # Compare lengths
        len1 = len(resp1.text)
        len2 = len(resp2.text)
        baseline_len = len(baseline.text)
        
        # Check for significant length difference
        if abs(len1 - len2) > 100:  # More than 100 characters difference
            return True
        
        # Check if one response is similar to baseline and other is not
        len_diff1 = abs(len1 - baseline_len)
        len_diff2 = abs(len2 - baseline_len)
        
        if (len_diff1 < 50 and len_diff2 > 200) or (len_diff2 < 50 and len_diff1 > 200):
            return True
        
        # Check status codes
        if resp1.status_code != resp2.status_code:
            return True
        
        return False
    
    def _calculate_error_confidence(self, error_msg: str) -> str:
        """Calculate confidence for error-based SQLi"""
        # High confidence errors
        high_confidence = [
            'SQL syntax',
            'ORA-',
            'unclosed quotation',
            'incorrect syntax'
        ]
        
        for indicator in high_confidence:
            if indicator.lower() in error_msg.lower():
                return 'High'
        
        return 'Medium'
    
    def _calculate_time_confidence(self, response_time: float, baseline_time: float) -> str:
        """Calculate confidence for time-based SQLi"""
        delay = response_time - baseline_time
        
        if delay > 10:
            return 'High'
        elif delay > 5:
            return 'Medium'
        else:
            return 'Low'