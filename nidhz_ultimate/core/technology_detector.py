"""
Advanced technology stack detector
"""

import re
from typing import List, Dict, Optional
import logging


class TechnologyDetector:
    """Detects web technologies from responses"""
    
    def __init__(self, http_client):
        self.client = http_client
        self.technology_patterns = self._load_technology_patterns()
    
    def detect(self, response) -> List[str]:
        """Detect technologies from HTTP response"""
        technologies = set()
        
        if not response:
            return list(technologies)
        
        # Check headers
        header_techs = self._detect_from_headers(response.headers)
        technologies.update(header_techs)
        
        # Check HTML content
        html_techs = self._detect_from_html(response.text)
        technologies.update(html_techs)
        
        # Check cookies
        cookie_techs = self._detect_from_cookies(response.headers)
        technologies.update(cookie_techs)
        
        # Check URL patterns
        url_techs = self._detect_from_url(response.url)
        technologies.update(url_techs)
        
        return sorted(list(technologies))
    
    def _detect_from_headers(self, headers: Dict) -> List[str]:
        """Detect technologies from HTTP headers"""
        techs = []
        server = headers.get('Server', '').lower()
        powered_by = headers.get('X-Powered-By', '').lower()
        
        # Web servers
        if 'apache' in server:
            techs.append('Apache')
            if 'coyote' in server:
                techs.append('Apache Tomcat')
        elif 'nginx' in server:
            techs.append('Nginx')
        elif 'iis' in server or 'microsoft-iis' in server:
            techs.append('IIS')
        elif 'lighttpd' in server:
            techs.append('Lighttpd')
        elif 'cloudflare' in server:
            techs.append('Cloudflare')
        
        # Application servers
        if 'tomcat' in server:
            techs.append('Tomcat')
        elif 'jetty' in server:
            techs.append('Jetty')
        elif 'glassfish' in server:
            techs.append('GlassFish')
        elif 'wildfly' in server:
            techs.append('WildFly')
        
        # Frameworks
        if 'express' in powered_by:
            techs.append('Express.js')
        if 'php' in powered_by:
            techs.append('PHP')
        if 'asp.net' in powered_by:
            techs.append('ASP.NET')
        if 'rails' in powered_by:
            techs.append('Ruby on Rails')
        
        # Check for specific headers
        if headers.get('X-AspNet-Version'):
            techs.append('ASP.NET')
        if headers.get('X-AspNetMvc-Version'):
            techs.append('ASP.NET MVC')
        if headers.get('X-Drupal-Cache'):
            techs.append('Drupal')
        if headers.get('X-Generator') and 'WordPress' in headers.get('X-Generator', ''):
            techs.append('WordPress')
        
        return techs
    
    def _detect_from_html(self, html: str) -> List[str]:
        """Detect technologies from HTML content"""
        techs = []
        html_lower = html.lower()
        
        # CMS detection
        if 'wp-content' in html_lower or 'wp-includes' in html_lower:
            techs.append('WordPress')
        if '/wp-json/' in html_lower:
            techs.append('WordPress REST API')
        
        if 'joomla' in html_lower:
            techs.append('Joomla')
        if 'drupal' in html_lower:
            techs.append('Drupal')
        if 'magento' in html_lower:
            techs.append('Magento')
        if 'shopify' in html_lower:
            techs.append('Shopify')
        if 'prestashop' in html_lower:
            techs.append('PrestaShop')
        
        # Framework detection
        if 'laravel' in html_lower:
            techs.append('Laravel')
        if 'symfony' in html_lower:
            techs.append('Symfony')
        if 'yii' in html_lower:
            techs.append('Yii')
        if 'codeigniter' in html_lower:
            techs.append('CodeIgniter')
        if 'cakephp' in html_lower:
            techs.append('CakePHP')
        
        # JavaScript frameworks
        if 'react' in html_lower or 'redux' in html_lower:
            techs.append('React')
        if 'vue' in html_lower or 'vue.js' in html_lower:
            techs.append('Vue.js')
        if 'angular' in html_lower:
            techs.append('Angular')
        if 'jquery' in html_lower:
            techs.append('jQuery')
        if 'backbone' in html_lower:
            techs.append('Backbone.js')
        if 'ember' in html_lower:
            techs.append('Ember.js')
        
        # Backend technologies
        if 'node' in html_lower or 'express' in html_lower:
            techs.append('Node.js')
        if 'django' in html_lower:
            techs.append('Django')
        if 'flask' in html_lower:
            techs.append('Flask')
        if 'spring' in html_lower:
            techs.append('Spring')
        if 'ruby' in html_lower or 'rails' in html_lower:
            techs.append('Ruby on Rails')
        
        # Analytics and tracking
        if 'google-analytics.com/ga.js' in html_lower:
            techs.append('Google Analytics')
        if 'googletagmanager.com/gtm.js' in html_lower:
            techs.append('Google Tag Manager')
        if 'facebook.com/tr' in html_lower:
            techs.append('Facebook Pixel')
        if 'hotjar' in html_lower:
            techs.append('Hotjar')
        
        # CDN detection
        if 'cloudflare' in html_lower:
            techs.append('Cloudflare')
        if 'cloudfront' in html_lower:
            techs.append('Amazon CloudFront')
        if 'akamai' in html_lower:
            techs.append('Akamai')
        if 'fastly' in html_lower:
            techs.append('Fastly')
        
        # Comment patterns
        comment_patterns = {
            'wordpress': r'WordPress',
            'joomla': r'Joomla',
            'drupal': r'Drupal!',
            'magento': r'Magento'
        }
        
        for tech, pattern in comment_patterns.items():
            if re.search(pattern, html, re.IGNORECASE):
                if tech.title() not in techs:
                    techs.append(tech.title())
        
        return techs
    
    def _detect_from_cookies(self, headers: Dict) -> List[str]:
        """Detect technologies from cookies"""
        techs = []
        cookies = headers.get('Set-Cookie', '')
        cookies_lower = cookies.lower()
        
        # CMS cookies
        if 'wordpress' in cookies_lower:
            techs.append('WordPress')
        if 'joomla' in cookies_lower:
            techs.append('Joomla')
        if 'drupal' in cookies_lower:
            techs.append('Drupal')
        if 'magento' in cookies_lower:
            techs.append('Magento')
        
        # Framework cookies
        if 'laravel' in cookies_lower:
            techs.append('Laravel')
        if 'sessionid' in cookies_lower and 'django' in cookies_lower:
            techs.append('Django')
        if 'express' in cookies_lower or 'connect.sid' in cookies_lower:
            techs.append('Express.js')
        
        # E-commerce
        if 'woocommerce' in cookies_lower:
            techs.append('WooCommerce')
        if 'shopify' in cookies_lower:
            techs.append('Shopify')
        
        return techs
    
    def _detect_from_url(self, url: str) -> List[str]:
        """Detect technologies from URL patterns"""
        techs = []
        url_lower = url.lower()
        
        # API frameworks
        if '/api/' in url_lower or '/v1/' in url_lower or '/v2/' in url_lower:
            techs.append('REST API')
        if '/graphql' in url_lower or '/gql' in url_lower:
            techs.append('GraphQL')
        if '/soap' in url_lower or '/wsdl' in url_lower:
            techs.append('SOAP')
        
        # Specific file extensions
        if '.aspx' in url_lower:
            techs.append('ASP.NET')
        if '.jsp' in url_lower or '.do' in url_lower:
            techs.append('Java')
        if '.php' in url_lower:
            techs.append('PHP')
        if '.py' in url_lower:
            techs.append('Python')
        if '.rb' in url_lower:
            techs.append('Ruby')
        
        return techs
    
    def _load_technology_patterns(self) -> Dict[str, List[str]]:
        """Load technology detection patterns"""
        return {
            'JavaScript Frameworks': {
                'react': ['react', 'redux'],
                'vue': ['vue', 'vue.js'],
                'angular': ['angular'],
                'jquery': ['jquery'],
                'backbone': ['backbone'],
                'ember': ['ember']
            },
            'Backend Frameworks': {
                'nodejs': ['node', 'express'],
                'django': ['django'],
                'flask': ['flask'],
                'spring': ['spring'],
                'laravel': ['laravel'],
                'rails': ['rails', 'ruby on rails']
            },
            'CMS': {
                'wordpress': ['wp-content', 'wp-includes', 'wp-json'],
                'joomla': ['joomla'],
                'drupal': ['drupal'],
                'magento': ['magento'],
                'shopify': ['shopify']
            },
            'Web Servers': {
                'apache': ['apache', 'coyote'],
                'nginx': ['nginx'],
                'iis': ['iis', 'microsoft-iis'],
                'lighttpd': ['lighttpd']
            },
            'Databases': {
                'mysql': ['mysql'],
                'postgresql': ['postgresql', 'postgres'],
                'mongodb': ['mongodb', 'mongo'],
                'redis': ['redis']
            }
        }