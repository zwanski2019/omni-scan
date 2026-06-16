"""
Utility functions for OMNI-SCAN
"""

import socket
import requests
import re
from typing import Dict, Optional, Tuple, List
from datetime import datetime
import json
from urllib.parse import urlparse

class GeoIP:
    """GeoIP lookup with caching"""
    
    def __init__(self):
        self.cache = {}
    
    def lookup(self, ip: str) -> Dict:
        """Lookup GeoIP information"""
        if ip in self.cache:
            return self.cache[ip]
        
        try:
            response = requests.get(
                f"https://ipapi.co/{ip}/json/",
                timeout=3
            )
            data = response.json()
            result = {
                "country": data.get("country_name", "Unknown"),
                "city": data.get("city", "Unknown"),
                "latitude": data.get("latitude", 0),
                "longitude": data.get("longitude", 0),
                "isp": data.get("org", "Unknown"),
                "asn": data.get("asn", "Unknown"),
                "timezone": data.get("timezone", "Unknown")
            }
            self.cache[ip] = result
            return result
        except Exception as e:
            return {
                "country": "Unknown",
                "city": "Unknown",
                "latitude": 0,
                "longitude": 0,
                "isp": "Unknown",
                "asn": "Unknown",
                "timezone": "Unknown"
            }

class BannerGrabber:
    """Banner grabbing utility"""
    
    @staticmethod
    def grab(ip: str, port: int, timeout: int = 3) -> Optional[str]:
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Send HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            
            data = sock.recv(2048)
            sock.close()
            
            return data.decode('utf-8', errors='ignore')[:1000]
        except Exception as e:
            return None
    
    @staticmethod
    def identify_service(banner: str, port: int) -> str:
        """Identify service from banner"""
        if not banner:
            return "Unknown"
        
        banner_lower = banner.lower()
        
        if "apache" in banner_lower:
            return "Apache HTTP Server"
        elif "nginx" in banner_lower:
            return "Nginx"
        elif "microsoft" in banner_lower or "iis" in banner_lower:
            return "IIS"
        elif "ssh" in banner_lower:
            return "OpenSSH"
        elif "mysql" in banner_lower:
            return "MySQL"
        elif "postgresql" in banner_lower:
            return "PostgreSQL"
        elif "mongodb" in banner_lower:
            return "MongoDB"
        elif "redis" in banner_lower:
            return "Redis"
        elif "ftp" in banner_lower:
            return "FTP"
        
        return "Unknown"

class URLParser:
    """Parse URLs and extract information"""
    
    @staticmethod
    def extract_endpoints(url: str, html: str) -> List[str]:
        """Extract potential API endpoints from HTML"""
        endpoints = set()
        
        # Find URLs in href attributes
        href_pattern = r'href=["\'](.*?)["\']'
        for match in re.finditer(href_pattern, html):
            endpoints.add(match.group(1))
        
        # Find API-like URLs
        api_pattern = r'["\']([/\w\-\.]*api[/\w\-\.]*)["\']'
        for match in re.finditer(api_pattern, html, re.IGNORECASE):
            endpoints.add(match.group(1))
        
        # Find OAuth endpoints
        oauth_patterns = [
            r'/oauth[/\w\-\.]*',
            r'/auth[/\w\-\.]*',
            r'/authorize',
            r'/token',
            r'/login',
            r'/authenticate'
        ]
        
        for pattern in oauth_patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                endpoints.add(match.group(0))
        
        return list(endpoints)
    
    @staticmethod
    def extract_oauth_config(html: str) -> Dict:
        """Extract OAuth configuration from HTML"""
        config = {}
        
        # Extract client_id
        client_id_pattern = r'client_id["\s:=]+([a-zA-Z0-9_\-\.]+)'
        match = re.search(client_id_pattern, html)
        if match:
            config['client_id'] = match.group(1)
        
        # Extract redirect_uri
        redirect_pattern = r'redirect_uri["\s:=]+([a-zA-Z0-9_\-\.:\/\?=&%]+)'
        match = re.search(redirect_pattern, html)
        if match:
            config['redirect_uri'] = match.group(1)
        
        # Extract scopes
        scopes_pattern = r'scopes?["\s:=]+([a-zA-Z0-9_\-\s]+)'
        match = re.search(scopes_pattern, html)
        if match:
            config['scopes'] = match.group(1)
        
        # Extract authorization endpoint
        auth_pattern = r'authorization_endpoint["\s:=]+([a-zA-Z0-9_\-\.:\/\?=&%]+)'
        match = re.search(auth_pattern, html)
        if match:
            config['authorization_endpoint'] = match.group(1)
        
        # Extract token endpoint
        token_pattern = r'token_endpoint["\s:=]+([a-zA-Z0-9_\-\.:\/\?=&%]+)'
        match = re.search(token_pattern, html)
        if match:
            config['token_endpoint'] = match.group(1)
        
        return config

class CloudDetector:
    """Detect cloud resources and exposed buckets"""
    
    @staticmethod
    def detect_s3_buckets(html: str, domain: str) -> List[Dict]:
        """Detect S3 buckets"""
        buckets = []
        
        # S3 URL patterns
        patterns = [
            r's3\.amazonaws\.com/([a-zA-Z0-9\-\.]+)',
            r'([a-zA-Z0-9\-\.]+)\.s3\.amazonaws\.com',
            r's3\-([a-zA-Z0-9\-]+)\.amazonaws\.com/([a-zA-Z0-9\-\.]+)',
            r'https?://([a-zA-Z0-9\-\.]+)\.s3-website[.-]([a-zA-Z0-9\-]+)',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, html):
                bucket_name = match.group(1) if match.lastindex >= 1 else match.group(0)
                buckets.append({
                    "provider": "AWS S3",
                    "bucket_name": bucket_name,
                    "url": match.group(0),
                    "type": "Storage"
                })
        
        return buckets
    
    @staticmethod
    def detect_gcs_buckets(html: str) -> List[Dict]:
        """Detect Google Cloud Storage buckets"""
        buckets = []
        
        patterns = [
            r'storage\.googleapis\.com/([a-zA-Z0-9\-\.]+)',
            r'([a-zA-Z0-9\-\.]+)\.storage\.googleapis\.com',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, html):
                bucket_name = match.group(1) if match.lastindex >= 1 else match.group(0)
                buckets.append({
                    "provider": "Google Cloud Storage",
                    "bucket_name": bucket_name,
                    "url": match.group(0),
                    "type": "Storage"
                })
        
        return buckets
    
    @staticmethod
    def detect_azure(html: str) -> List[Dict]:
        """Detect Azure resources"""
        resources = []
        
        patterns = [
            r'([a-zA-Z0-9\-]+)\.blob\.core\.windows\.net',
            r'([a-zA-Z0-9\-]+)\.file\.core\.windows\.net',
            r'([a-zA-Z0-9\-]+)\.database\.windows\.net',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, html):
                resources.append({
                    "provider": "Azure",
                    "resource_name": match.group(1),
                    "url": match.group(0),
                    "type": "Cloud Resource"
                })
        
        return resources

class WellKnownParser:
    """Parse .well-known endpoints"""
    
    @staticmethod
    def parse_openid_config(config: Dict) -> Dict:
        """Parse OpenID Connect configuration"""
        return {
            "issuer": config.get("issuer"),
            "authorization_endpoint": config.get("authorization_endpoint"),
            "token_endpoint": config.get("token_endpoint"),
            "userinfo_endpoint": config.get("userinfo_endpoint"),
            "jwks_uri": config.get("jwks_uri"),
            "scopes_supported": config.get("scopes_supported", []),
            "response_types_supported": config.get("response_types_supported", []),
            "grant_types_supported": config.get("grant_types_supported", []),
        }

class VersionDetector:
    """Detect service versions from banners and responses"""
    
    @staticmethod
    def extract_version(service: str, banner: str) -> Optional[str]:
        """Extract version from banner"""
        if not banner:
            return None
        
        patterns = {
            "Apache": r'Apache/([0-9\.]+)',
            "Nginx": r'nginx/([0-9\.]+)',
            "IIS": r'IIS/([0-9\.]+)',
            "OpenSSH": r'OpenSSH[_-]([0-9\.]+)',
            "MySQL": r'MySQL/([0-9\.]+)',
            "PostgreSQL": r'PostgreSQL/([0-9\.]+)',
            "PHP": r'PHP/([0-9\.]+)',
            "Node.js": r'Node\.js/([0-9\.]+)',
        }
        
        for service_name, pattern in patterns.items():
            if service_name.lower() in service.lower():
                match = re.search(pattern, banner)
                if match:
                    return match.group(1)
        
        # Generic version pattern
        version_pattern = r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
        match = re.search(version_pattern, banner)
        if match:
            return match.group(1)
        
        return None

class IOTDetector:
    """Detect IoT devices and common vulnerabilities"""
    
    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "12345"),
        ("root", "root"),
        ("root", "password"),
        ("root", "admin"),
        ("root", "toor"),
        ("pi", "raspberry"),
        ("admin", ""),
        ("root", ""),
        ("user", "user"),
        ("guest", "guest"),
        ("administrator", "password"),
        ("Administrator", "admin"),
    ]
    
    DEVICE_SIGNATURES = {
        "Hikvision": [
            "Hikvision",
            "HIKVISION",
            "/ISAPI/",
        ],
        "Dahua": [
            "Dahua",
            "dahua",
            "DH-",
        ],
        "Ubiquiti": [
            "Ubiquiti",
            "ubiquiti",
            "UniFi",
        ],
        "TP-Link": [
            "TP-Link",
            "tp-link",
            "TL-",
        ],
        "Netgear": [
            "Netgear",
            "NETGEAR",
            "netgear",
        ],
        "D-Link": [
            "D-Link",
            "d-link",
            "D-Link",
        ],
        "Axis": [
            "Axis",
            "AXIS",
        ],
    }
    
    @staticmethod
    def detect_device(banner: str, port: int) -> Optional[str]:
        """Detect IoT device type"""
        if not banner:
            return None
        
        for device_type, signatures in IOTDetector.DEVICE_SIGNATURES.items():
            for sig in signatures:
                if sig in banner:
                    return device_type
        
        return None

def format_timestamp(ts: str) -> str:
    """Format timestamp for display"""
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return ts

def severity_color(severity: str) -> str:
    """Get color for severity level"""
    colors = {
        "critical": "#FF0000",
        "high": "#FF6600",
        "medium": "#FFCC00",
        "low": "#00CC00",
        "info": "#0099FF"
    }
    return colors.get(severity.lower(), "#999999")

def format_bytes(bytes_val: int) -> str:
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.2f} TB"
