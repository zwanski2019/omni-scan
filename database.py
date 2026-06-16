"""
Database module for OMNI-SCAN
Handles all SQLite operations
"""

import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import threading

class Database:
    def __init__(self, db_path: str = "omni_scan.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.init_tables()
    
    def _get_conn(self):
        """Get thread-safe connection"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_tables(self):
        """Initialize all tables"""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        # Hosts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                hostname TEXT,
                country TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                isp TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_alive BOOLEAN DEFAULT 0,
                os TEXT,
                os_accuracy INTEGER,
                notes TEXT
            )
        ''')
        
        # Ports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                port INTEGER NOT NULL,
                service TEXT,
                banner TEXT,
                version TEXT,
                protocol TEXT DEFAULT 'TCP',
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_open BOOLEAN DEFAULT 0,
                FOREIGN KEY (host_id) REFERENCES hosts(id),
                UNIQUE(host_id, port, protocol)
            )
        ''')
        
        # Vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                port_id INTEGER,
                cve_id TEXT,
                severity TEXT,
                description TEXT,
                proof TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (host_id) REFERENCES hosts(id),
                FOREIGN KEY (port_id) REFERENCES ports(id)
            )
        ''')
        
        # Credentials found table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                port_id INTEGER,
                service TEXT,
                username TEXT,
                password TEXT,
                found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (host_id) REFERENCES hosts(id),
                FOREIGN KEY (port_id) REFERENCES ports(id)
            )
        ''')
        
        # OAuth endpoints table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS oauth_endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                endpoint TEXT,
                auth_type TEXT,
                client_id TEXT,
                redirect_uri TEXT,
                scopes TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            )
        ''')
        
        # Cloud resources table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cloud_resources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                resource_type TEXT,
                resource_name TEXT,
                cloud_provider TEXT,
                bucket_name TEXT,
                is_public BOOLEAN,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            )
        ''')
        
        # IoT devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iot_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                device_type TEXT,
                model TEXT,
                firmware_version TEXT,
                accessible BOOLEAN DEFAULT 0,
                default_creds TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            )
        ''')
        
        # Scan sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                scan_type TEXT,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                duration_seconds INTEGER,
                hosts_found INTEGER,
                ports_found INTEGER,
                vulns_found INTEGER,
                status TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def insert_host(self, ip: str) -> int:
        """Insert or get host ID"""
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('INSERT OR IGNORE INTO hosts (ip) VALUES (?)', (ip,))
            conn.commit()
            cursor.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
            result = cursor.fetchone()
            conn.close()
            return result[0] if result else None
    
    def update_host(self, ip: str, hostname: str = None, country: str = None, 
                   city: str = None, isp: str = None, os: str = None, os_accuracy: int = None):
        """Update host information"""
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            updates = []
            params = []
            
            if hostname:
                updates.append("hostname = ?")
                params.append(hostname)
            if country:
                updates.append("country = ?")
                params.append(country)
            if city:
                updates.append("city = ?")
                params.append(city)
            if isp:
                updates.append("isp = ?")
                params.append(isp)
            if os:
                updates.append("os = ?")
                params.append(os)
            if os_accuracy is not None:
                updates.append("os_accuracy = ?")
                params.append(os_accuracy)
            
            if updates:
                updates.append("last_seen = CURRENT_TIMESTAMP")
                params.append(ip)
                query = f"UPDATE hosts SET {', '.join(updates)} WHERE ip = ?"
                cursor.execute(query, params)
                conn.commit()
            
            conn.close()
    
    def update_host_alive(self, ip: str):
        """Mark host as alive"""
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE hosts 
                SET last_seen = CURRENT_TIMESTAMP, is_alive = 1
                WHERE ip = ?
            ''', (ip,))
            conn.commit()
            conn.close()
    
    def insert_port(self, host_id: int, port: int, service: str, banner: str = None, version: str = None):
        """Insert open port"""
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO ports 
                (host_id, port, service, banner, version, is_open, last_seen)
                VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
            ''', (host_id, port, service, banner, version))
            conn.commit()
            result = cursor.lastrowid
            conn.close()
            return result
    
    def insert_vulnerability(self, host_id: int, port_id: int, cve_id: str, 
                            severity: str, description: str, proof: str = None):
        """Insert vulnerability"""
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO vulnerabilities 
                (host_id, port_id, cve_id, severity, description, proof)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (host_id, port_id, cve_id, severity, description, proof))
            conn.commit()
            result = cursor.lastrowid
            conn.close()
            return result
    
    def insert_credentials(self, host_id: int, port_id: int, service: str, 
                          username: str, password: str):
        """Insert found credentials"""
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO credentials 
                (host_id, port_id, service, username, password)
                VALUES (?, ?, ?, ?, ?)
            ''', (host_id, port_id, service, username, password))
            conn.commit()
            conn.close()
    
    def insert_oauth(self, host_id: int, endpoint: str, auth_type: str, 
                    client_id: str = None, redirect_uri: str = None, scopes: str = None):
        """Insert OAuth endpoint"""
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO oauth_endpoints 
                (host_id, endpoint, auth_type, client_id, redirect_uri, scopes)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (host_id, endpoint, auth_type, client_id, redirect_uri, scopes))
            conn.commit()
            conn.close()
    
    def insert_cloud_resource(self, host_id: int, resource_type: str, resource_name: str,
                             cloud_provider: str, bucket_name: str = None, is_public: bool = False):
        """Insert cloud resource"""
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO cloud_resources 
                (host_id, resource_type, resource_name, cloud_provider, bucket_name, is_public)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (host_id, resource_type, resource_name, cloud_provider, bucket_name, is_public))
            conn.commit()
            conn.close()
    
    def insert_iot(self, host_id: int, device_type: str, model: str, 
                  firmware: str, accessible: bool, default_creds: str = None):
        """Insert IoT device"""
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO iot_devices 
                (host_id, device_type, model, firmware_version, accessible, default_creds)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (host_id, device_type, model, firmware, 1 if accessible else 0, default_creds))
            conn.commit()
            conn.close()
    
    def get_host(self, ip: str) -> Dict:
        """Get host details"""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM hosts WHERE ip = ?', (ip,))
        result = cursor.fetchone()
        conn.close()
        return dict(result) if result else None
    
    def get_host_ports(self, host_id: int) -> List[Dict]:
        """Get all ports for a host"""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM ports WHERE host_id = ? AND is_open = 1', (host_id,))
        results = cursor.fetchall()
        conn.close()
        return [dict(r) for r in results]
    
    def get_host_vulns(self, host_id: int) -> List[Dict]:
        """Get vulnerabilities for a host"""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT v.*, p.port, p.service 
            FROM vulnerabilities v
            LEFT JOIN ports p ON v.port_id = p.id
            WHERE v.host_id = ?
        ''', (host_id,))
        results = cursor.fetchall()
        conn.close()
        return [dict(r) for r in results]
    
    def get_host_creds(self, host_id: int) -> List[Dict]:
        """Get credentials for a host"""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT c.*, p.port, p.service 
            FROM credentials c
            LEFT JOIN ports p ON c.port_id = p.id
            WHERE c.host_id = ?
        ''', (host_id,))
        results = cursor.fetchall()
        conn.close()
        return [dict(r) for r in results]
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        conn = self._get_conn()
        cursor = conn.cursor()
        stats = {}
        
        cursor.execute("SELECT COUNT(*) FROM hosts")
        stats['total_hosts'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM hosts WHERE is_alive = 1")
        stats['alive_hosts'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM ports WHERE is_open = 1")
        stats['open_ports'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        stats['vulnerabilities'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM credentials")
        stats['credentials_found'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM oauth_endpoints")
        stats['oauth_endpoints'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM cloud_resources")
        stats['cloud_resources'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM iot_devices WHERE accessible = 1")
        stats['iot_devices'] = cursor.fetchone()[0]
        
        conn.close()
        return stats
    
    def export_json(self, host_id: int) -> Dict:
        """Export host data as JSON"""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM hosts WHERE id = ?', (host_id,))
        host = dict(cursor.fetchone()) if cursor.fetchone() else {}
        
        cursor.execute('SELECT * FROM ports WHERE host_id = ?', (host_id,))
        ports = [dict(r) for r in cursor.fetchall()]
        
        cursor.execute('SELECT * FROM vulnerabilities WHERE host_id = ?', (host_id,))
        vulns = [dict(r) for r in cursor.fetchall()]
        
        cursor.execute('SELECT * FROM credentials WHERE host_id = ?', (host_id,))
        creds = [dict(r) for r in cursor.fetchall()]
        
        cursor.execute('SELECT * FROM oauth_endpoints WHERE host_id = ?', (host_id,))
        oauth = [dict(r) for r in cursor.fetchall()]
        
        cursor.execute('SELECT * FROM cloud_resources WHERE host_id = ?', (host_id,))
        cloud = [dict(r) for r in cursor.fetchall()]
        
        cursor.execute('SELECT * FROM iot_devices WHERE host_id = ?', (host_id,))
        iot = [dict(r) for r in cursor.fetchall()]
        
        conn.close()
        
        return {
            "host": host,
            "ports": ports,
            "vulnerabilities": vulns,
            "credentials": creds,
            "oauth_endpoints": oauth,
            "cloud_resources": cloud,
            "iot_devices": iot,
            "exported_at": datetime.now().isoformat()
        }
    
    def clear_all(self):
        """Clear all data"""
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('DELETE FROM vulnerabilities')
            cursor.execute('DELETE FROM credentials')
            cursor.execute('DELETE FROM oauth_endpoints')
            cursor.execute('DELETE FROM cloud_resources')
            cursor.execute('DELETE FROM iot_devices')
            cursor.execute('DELETE FROM ports')
            cursor.execute('DELETE FROM hosts')
            cursor.execute('DELETE FROM scan_sessions')
            conn.commit()
            conn.close()
