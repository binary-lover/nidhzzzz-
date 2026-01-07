"""
Advanced XSS vulnerability scanner
"""

import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode
import logging

from utils.http_client import HTTPClient
from utils.wordlist_manager import WordlistManager


class XSSScanner:
    """Advanced XSS scanner with context awareness"""
    
    def __init__(self, 
                 http_client: HTTPClient,
                 logger: Optional[logging.Logger] = None):
        
        self.client = http_client
        self.logger = logger or logging.getLogger(__name__)
        self.wordlist_manager = WordlistManager()
        
        # Load payloads
        self.payloads = self.wordlist_manager.get_xss_payloads()
        
        # XSS indicators
        self.reflection_indicators = [
            r'<script[^>]*>',
            r'javascript:',
            r'on\w+\s*=',
            r'alert\(',
            r'prompt\(',
            r'confirm\(',
            r'document\.',
            r'window\.',
            r'location\.',
            r'eval\(',
            r'setTimeout\(',
            r'setInterval\('
        ]
    
    def scan(self, url: str) -> List[Dict]:
        """Scan URL for XSS vulnerabilities"""
        self.logger.info(f"Scanning for XSS: {url}")
        
        vulnerabilities = []
        
        # Get page content
        try:
            response = self.client.get(url)
            if not response:
                return vulnerabilities
            
            # Test URL parameters
            url_vulns = self._test_url_parameters(url)
            vulnerabilities.extend(url_vulns)
            
            # Test forms
            form_vulns = self._test_forms(url, response.text)
            vulnerabilities.extend(form_vulns)
            
            # Check for DOM XSS patterns
            dom_vulns = self._check_dom_xss(response.text)
            vulnerabilities.extend(dom_vulns)
            
        except Exception as e:
            self.logger.error(f"XSS scan failed for {url}: {e}")
        
        return vulnerabilities
    
    def _test_url_parameters(self, url: str) -> List[Dict]:
        """Test URL parameters for XSS"""
        vulnerabilities = []
        parsed = urlparse(url)
        
        if not parsed.query:
            return vulnerabilities
        
        params = parse_qs(parsed.query)
        
        for param_name in params:
            self.logger.debug(f"Testing parameter: {param_name}")
            
            # Test each payload
            for payload in self.payloads[:20]:  # Limit to 20 payloads for speed
                # Build test URL
                test_params = params.copy()
                test_params[param_name] = payload
                
                test_url = parsed._replace(
                    query=urlencode(test_params, doseq=True)
                ).geturl()
                
                # Send request
                try:
                    response = self.client.get(test_url)
                    if response and self._is_xss_reflected(payload, response):
                        
                        # Calculate confidence
                        confidence = self._calculate_confidence(payload, response)
                        
                        vulnerabilities.append({
                            'type': 'XSS',
                            'subtype': 'Reflected',
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload[:100],  # Truncate long payloads
                            'confidence': confidence,
                            'evidence': self._extract_evidence(payload, response.text)
                        })
                        
                        self.logger.info(f"Found XSS in {param_name}: {confidence}")
                        break  # Stop after first successful payload
                
                except Exception as e:
                    self.logger.debug(f"Failed to test {param_name}: {e}")
        
        return vulnerabilities
    
    def _test_forms(self, url: str, html: str) -> List[Dict]:
        """Test HTML forms for XSS"""
        vulnerabilities = []
        
        # Extract forms from HTML
        forms = self._extract_forms(html)
        
        for form in forms:
            form_vulns = self._test_form(url, form)
            vulnerabilities.extend(form_vulns)
        
        return vulnerabilities
    
    def _extract_forms(self, html: str) -> List[Dict]:
        """Extract forms from HTML"""
        forms = []
        form_pattern = r'<form[^>]*>.*?</form>'
        
        import re
        form_matches = re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL)
        
        for match in form_matches:
            form_html = match.group()
            
            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else ''
            
            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else 'GET'
            
            # Extract inputs
            inputs = []
            input_pattern = r'<input[^>]*>'
            input_matches = re.finditer(input_pattern, form_html, re.IGNORECASE)
            
            for input_match in input_matches:
                input_html = input_match.group()
                
                # Extract name
                name_match = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                if name_match:
                    inputs.append({
                        'name': name_match.group(1),
                        'html': input_html
                    })
            
            forms.append({
                'action': action,
                'method': method,
                'inputs': inputs,
                'html': form_html[:500]  # Truncate
            })
        
        return forms
    
    def _test_form(self, base_url: str, form: Dict) -> List[Dict]:
        """Test a single form for XSS"""
        vulnerabilities = []
        
        # Build form data
        form_data = {}
        for inp in form['inputs']:
            form_data[inp['name']] = 'test'
        
        # Test each input
        for inp in form['inputs']:
            input_name = inp['name']
            
            for payload in self.payloads[:10]:  # Limit to 10 payloads
                # Create test data
                test_data = form_data.copy()
                test_data[input_name] = payload
                
                # Determine action URL
                if form['action']:
                    action_url = form['action']
                    if not action_url.startswith(('http://', 'https://')):
                        action_url = urljoin(base_url, action_url)
                else:
                    action_url = base_url
                
                # Send request
                try:
                    if form['method'] == 'POST':
                        response = self.client.post(action_url, data=test_data)
                    else:
                        response = self.client.get(action_url, params=test_data)
                    
                    if response and self._is_xss_reflected(payload, response):
                        confidence = self._calculate_confidence(payload, response)
                        
                        vulnerabilities.append({
                            'type': 'XSS',
                            'subtype': 'Form-based',
                            'url': action_url,
                            'parameter': input_name,
                            'method': form['method'],
                            'payload': payload[:100],
                            'confidence': confidence,
                            'evidence': self._extract_evidence(payload, response.text)
                        })
                        
                        self.logger.info(f"Found form XSS in {input_name}")
                        break
                
                except Exception as e:
                    self.logger.debug(f"Form test failed: {e}")
        
        return vulnerabilities
    
    def _check_dom_xss(self, html: str) -> List[Dict]:
        """Check for DOM XSS patterns"""
        vulnerabilities = []
        
        # DOM XSS sink patterns
        dom_patterns = [
            (r'document\.write\([^)]*\)', 'document.write'),
            (r'document\.writeln\([^)]*\)', 'document.writeln'),
            (r'innerHTML\s*=', 'innerHTML'),
            (r'outerHTML\s*=', 'outerHTML'),
            (r'eval\([^)]*\)', 'eval'),
            (r'setTimeout\([^)]*\)', 'setTimeout'),
            (r'setInterval\([^)]*\)', 'setInterval'),
            (r'Function\([^)]*\)', 'Function constructor'),
            (r'location\.(href|hash|search)\s*=', 'location assignment'),
            (r'window\.open\([^)]*\)', 'window.open'),
            (r'\.src\s*=', 'src attribute'),
            (r'postMessage\([^)]*\)', 'postMessage')
        ]
        
        for pattern, sink_name in dom_patterns:
            matches = re.finditer(pattern, html, re.IGNORECASE)
            
            for match in matches:
                context = match.group()
                
                # Check if user input might reach this sink
                if any(indicator in context.lower() for indicator in ['location', 'document.', 'window.']):
                    
                    vulnerabilities.append({
                        'type': 'XSS',
                        'subtype': 'DOM-based',
                        'sink': sink_name,
                        'confidence': 'Medium',
                        'evidence': context[:200],
                        'note': 'Potential DOM XSS sink found'
                    })
        
        return vulnerabilities
    
    def _is_xss_reflected(self, payload: str, response) -> bool:
        """Check if payload is reflected in response"""
        # Check response body
        if payload in response.text:
            return True
        
        # Check for encoded versions
        encoded_variations = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('<', '%3C').replace('>', '%3E'),
            payload.replace('<', '\\u003C').replace('>', '\\u003E')
        ]
        
        for encoded in encoded_variations:
            if encoded in response.text:
                return True
        
        # Check for partial reflection
        if len(payload) > 10:
            # Check first and last 5 chars
            start = payload[:5]
            end = payload[-5:]
            if start in response.text and end in response.text:
                return True
        
        return False
    
    def _calculate_confidence(self, payload: str, response) -> str:
        """Calculate confidence level for XSS finding"""
        # High confidence indicators
        high_indicators = [
            '<script>alert',
            '<script>prompt',
            '<script>confirm',
            'javascript:alert',
            'onload=alert',
            'onerror=alert'
        ]
        
        for indicator in high_indicators:
            if indicator in payload.lower():
                return 'High'
        
        # Check if payload triggers JavaScript execution
        if self._triggers_js_execution(payload, response):
            return 'High'
        
        # Medium confidence
        medium_indicators = [
            '<script>',
            'javascript:',
            'onload=',
            'onerror=',
            'onmouseover='
        ]
        
        for indicator in medium_indicators:
            if indicator in payload.lower():
                return 'Medium'
        
        return 'Low'
    
    def _triggers_js_execution(self, payload: str, response) -> bool:
        """Check if payload likely triggers JavaScript execution"""
        # This is a simplified check
        # In reality, you'd need a browser engine to properly test
        
        # Check for script tags in reflection
        if '<script>' in payload and '<script>' in response.text:
            return True
        
        # Check for event handlers
        event_handlers = ['onload', 'onerror', 'onclick', 'onmouseover']
        for handler in event_handlers:
            if handler in payload and handler in response.text:
                return True
        
        return False
    
    def _extract_evidence(self, payload: str, response_text: str) -> str:
        """Extract evidence of reflection"""
        # Find the reflection context
        lines = response_text.split('\n')
        
        for i, line in enumerate(lines):
            if payload in line:
                # Get context (2 lines before and after)
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                context = '\n'.join(lines[start:end])
                return context[:500]  # Truncate
        
        return "Payload reflected in response"