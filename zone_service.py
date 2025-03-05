import json
import sys
import os
import time
import threading
import hashlib
import shutil
import sqlite3
import requests
import logging
import argparse
import datetime as dt
from typing import Dict, List, Set, Tuple, Optional, Any, Union
from datetime import datetime, timedelta

try:
    import pytz
    HAS_PYTZ = True
except ImportError:
    HAS_PYTZ = False

import download

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("zone_service.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("zone_service")

class ZoneChangeTracker:
    """Track changes between different versions of zone files"""
    
    def __init__(self, db_conn, archive_dir):
        self.db_conn = db_conn
        self.archive_dir = archive_dir
        self._ensure_dirs()
        self._ensure_tables()
    
    def _ensure_dirs(self):
        """Ensure archive directories exist"""
        if not os.path.exists(self.archive_dir):
            os.makedirs(self.archive_dir)
            
        for dir_name in ['current', 'previous', 'diffs']:
            path = os.path.join(self.archive_dir, dir_name)
            if not os.path.exists(path):
                os.makedirs(path)
    
    def _ensure_tables(self):
        """Ensure required tables exist in the database"""
        cursor = self.db_conn.cursor()
        
        # Table to track domain states for change detection
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS domain_states (
            domain_name TEXT PRIMARY KEY,
            tld TEXT NOT NULL,
            last_updated TIMESTAMP NOT NULL,
            hash TEXT NOT NULL,
            status TEXT NOT NULL
        )
        ''')
        
        # Table to track detected changes
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS change_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_name TEXT NOT NULL,
            tld TEXT NOT NULL,
            change_type TEXT NOT NULL,
            change_time TIMESTAMP NOT NULL,
            old_hash TEXT,
            new_hash TEXT,
            details TEXT,
            notified BOOLEAN DEFAULT 0
        )
        ''')
        
        # Create indices for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain_states_tld ON domain_states(tld)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_change_events_domain ON change_events(domain_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_change_events_notified ON change_events(notified)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_change_events_tld ON change_events(tld)')
        
        self.db_conn.commit()
    
    def archive_zonefile(self, zonefile_id, filename, tld):
        """Archive a zonefile for change tracking"""
        cursor = self.db_conn.cursor()
        
        # Get the zonefile path
        zonefile_path = os.path.join(download.working_directory, 'zonefiles', filename)
        
        # Move current version to previous
        current_path = os.path.join(self.archive_dir, 'current', f"{tld}.txt.gz")
        previous_path = os.path.join(self.archive_dir, 'previous', f"{tld}.txt.gz")
        
        if os.path.exists(current_path):
            # If there's already a current version, move it to previous
            if os.path.exists(previous_path):
                os.remove(previous_path)
            shutil.copy(current_path, previous_path)
        
        # Copy new file to current
        shutil.copy(zonefile_path, current_path)
        
        logger.info(f"Archived zonefile for {tld}")
        return current_path, previous_path
    
    def compute_domain_hash(self, domain_name, records):
        """Compute a hash for a domain's records to detect changes"""
        # Sort records by type and data for consistent hashing
        sorted_records = sorted(records, key=lambda r: (r['record_type'], r['ttl'], r['record_data']))
        
        # Create a string representation
        record_str = ";".join([
            f"{r['record_type']}:{r['ttl']}:{r['record_data']}"
            for r in sorted_records
        ])
        
        # Compute hash
        return hashlib.sha256(record_str.encode('utf-8')).hexdigest()
    
    def detect_changes(self, tld, new_zonefile_id):
        """Detect changes between the current and previous versions of a zonefile"""
        cursor = self.db_conn.cursor()
        now = datetime.now()
        
        # Get all domains and their records from the new zonefile
        cursor.execute('''
        SELECT domain_name, record_type, ttl, record_data
        FROM dns_records
        WHERE zonefile_id = ?
        ORDER BY domain_name
        ''', (new_zonefile_id,))
        
        # Group records by domain
        new_domains = {}
        current_domain = None
        current_records = []
        
        for row in cursor.fetchall():
            domain, record_type, ttl, record_data = row
            
            if domain != current_domain:
                if current_domain:
                    # Calculate hash and store
                    new_domains[current_domain] = {
                        'records': current_records,
                        'hash': self.compute_domain_hash(current_domain, current_records)
                    }
                
                current_domain = domain
                current_records = []
            
            current_records.append({
                'record_type': record_type,
                'ttl': ttl,
                'record_data': record_data
            })
        
        # Don't forget the last domain
        if current_domain:
            new_domains[current_domain] = {
                'records': current_records,
                'hash': self.compute_domain_hash(current_domain, current_records)
            }
        
        # Get existing domain states
        cursor.execute('''
        SELECT domain_name, hash, status
        FROM domain_states
        WHERE tld = ?
        ''', (tld,))
        
        old_domains = {row[0]: {'hash': row[1], 'status': row[2]} for row in cursor.fetchall()}
        
        # Track changes
        changes = []
        
        # Find new and changed domains
        for domain, data in new_domains.items():
            if domain not in old_domains:
                # New domain
                changes.append({
                    'domain_name': domain,
                    'tld': tld,
                    'change_type': 'new_domain',
                    'change_time': now,
                    'old_hash': None,
                    'new_hash': data['hash'],
                    'details': json.dumps({
                        'records': data['records']
                    })
                })
                
                # Add to domain states
                cursor.execute('''
                INSERT INTO domain_states (domain_name, tld, last_updated, hash, status)
                VALUES (?, ?, ?, ?, ?)
                ''', (domain, tld, now, data['hash'], 'active'))
            
            elif old_domains[domain]['hash'] != data['hash']:
                # Changed domain
                changes.append({
                    'domain_name': domain,
                    'tld': tld,
                    'change_type': 'record_change',
                    'change_time': now,
                    'old_hash': old_domains[domain]['hash'],
                    'new_hash': data['hash'],
                    'details': json.dumps({
                        'records': data['records']
                    })
                })
                
                # Update domain state
                cursor.execute('''
                UPDATE domain_states
                SET hash = ?, last_updated = ?
                WHERE domain_name = ?
                ''', (data['hash'], now, domain))
        
        # Find deleted domains
        for domain, data in old_domains.items():
            if domain not in new_domains and data['status'] == 'active':
                # Deleted domain
                changes.append({
                    'domain_name': domain,
                    'tld': tld,
                    'change_type': 'deleted_domain',
                    'change_time': now,
                    'old_hash': data['hash'],
                    'new_hash': None,
                    'details': None
                })
                
                # Update domain state
                cursor.execute('''
                UPDATE domain_states
                SET status = ?, last_updated = ?
                WHERE domain_name = ?
                ''', ('deleted', now, domain))
        
        # Save changes to database
        for change in changes:
            cursor.execute('''
            INSERT INTO change_events 
            (domain_name, tld, change_type, change_time, old_hash, new_hash, details, notified)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            ''', (
                change['domain_name'], change['tld'], change['change_type'],
                change['change_time'], change['old_hash'], change['new_hash'],
                change['details']
            ))
        
        self.db_conn.commit()
        logger.info(f"Detected {len(changes)} changes in {tld} zone")
        return len(changes)
    
    def send_webhook_notifications(self, webhooks):
        """Send notifications about changes to configured webhooks"""
        cursor = self.db_conn.cursor()
        
        # Get all unnotified changes
        cursor.execute('''
        SELECT id, domain_name, tld, change_type, change_time, details
        FROM change_events
        WHERE notified = 0
        ORDER BY tld, change_type, change_time
        ''')
        
        all_changes = cursor.fetchall()
        if not all_changes:
            logger.info("No pending notifications to send")
            return 0
        
        # Group changes by TLD and change type for efficient notification
        changes_by_tld_type = {}
        for change_id, domain, tld, change_type, change_time, details in all_changes:
            key = (tld, change_type)
            if key not in changes_by_tld_type:
                changes_by_tld_type[key] = []
            
            change = {
                'id': change_id,
                'domain': domain,
                'tld': tld,
                'change_type': change_type,
                'timestamp': change_time.isoformat()
            }
            
            # Add details for non-deletion events
            if details:
                change['details'] = json.loads(details)
            
            changes_by_tld_type[key].append(change)
        
        notification_count = 0
        
        # Process each webhook
        for webhook in webhooks:
            url = webhook.get('url')
            if not url:
                continue
                
            events = webhook.get('events', [])
            tlds = webhook.get('tlds', [])
            max_batch = webhook.get('max_batch_size', 1000)
            headers = webhook.get('headers', {})
            
            # Filter changes by the webhook's configuration
            webhook_changes = []
            for (tld, change_type), changes in changes_by_tld_type.items():
                if (not tlds or tld in tlds) and (not events or change_type in events):
                    webhook_changes.extend(changes)
            
            if not webhook_changes:
                continue
            
            # Process in batches
            for i in range(0, len(webhook_changes), max_batch):
                batch = webhook_changes[i:i+max_batch]
                
                # Prepare payload
                payload = {
                    'timestamp': datetime.now().isoformat(),
                    'changes': batch
                }
                
                try:
                    # Send the notification
                    response = requests.post(url, json=payload, headers=headers, timeout=30)
                    
                    if response.status_code >= 200 and response.status_code < 300:
                        # Mark changes as notified on success
                        change_ids = [change['id'] for change in batch]
                        placeholders = ', '.join(['?'] * len(change_ids))
                        cursor.execute(f'''
                        UPDATE change_events
                        SET notified = 1
                        WHERE id IN ({placeholders})
                        ''', change_ids)
                        
                        self.db_conn.commit()
                        notification_count += len(batch)
                        logger.info(f"Successfully sent {len(batch)} notifications to webhook {url}")
                    else:
                        logger.error(f"Failed to send notifications to webhook {url}: {response.status_code} - {response.text}")
                
                except Exception as e:
                    logger.error(f"Error sending notifications to webhook {url}: {str(e)}")
        
        return notification_count


class ZoneService:
    """Service to automatically download and process zone files on a schedule"""
    
    def __init__(self, config_path="config.json"):
        self.config_path = config_path
        self.running = False
        self.scheduler_thread = None
        self.load_config()
        self.setup_database()
        
        # Initialize tracker if change tracking is enabled
        if self.change_tracking_enabled:
            self.tracker = ZoneChangeTracker(self.db_conn, self.archive_dir)
    
    def load_config(self):
        """Load configuration from config file"""
        try:
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)
            
            logger.info("Configuration loaded successfully")
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
            sys.exit(1)
        
        # Extract configuration
        self.username = self.config.get('icann.account.username')
        self.password = self.config.get('icann.account.password')
        self.authen_base_url = self.config.get('authentication.base.url')
        self.czds_base_url = self.config.get('czds.base.url')
        self.working_directory = self.config.get('working.directory', '.')
        
        # Database settings
        self.db_enabled = self.config.get('database.enabled', True)  # Service requires database
        self.db_path = self.config.get('database.path', os.path.join(self.working_directory, 'zonefiles.db'))
        
        # Service settings
        self.service_enabled = self.config.get('service.enabled', False)
        self.download_start_time = self.config.get('service.download_start_time', '00:15:00')
        self.download_end_time = self.config.get('service.download_end_time', '06:45:00')
        self.timezone = self.config.get('service.timezone', 'UTC')
        
        # Change tracking
        self.change_tracking_enabled = self.config.get('service.change_tracking.enabled', True)
        self.archive_dir = self.config.get('service.change_tracking.archive_dir', 
                                          os.path.join(self.working_directory, 'archive'))
        
        # Webhooks
        self.webhooks = self.config.get('webhooks', [])
        
        # Required fields validation
        if not self.username or not self.password or not self.authen_base_url or not self.czds_base_url:
            logger.error("Required configuration parameters missing")
            sys.exit(1)
    
    def setup_database(self):
        """Set up the SQLite database for zone data and change tracking"""
        if not self.db_enabled:
            logger.error("Database is required for the service to function")
            sys.exit(1)
        
        try:
            self.db_conn = sqlite3.connect(self.db_path)
            self.db_conn.execute("PRAGMA journal_mode = WAL")
            self.db_conn.execute("PRAGMA synchronous = NORMAL")
            
            cursor = self.db_conn.cursor()
            
            # Create zone files table if it doesn't exist
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS zonefiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                tld TEXT NOT NULL,
                download_date TIMESTAMP NOT NULL,
                record_count INTEGER NOT NULL,
                status TEXT DEFAULT 'complete',
                last_processed_line INTEGER DEFAULT 0
            )
            ''')
            
            # Create DNS records table if it doesn't exist
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                zonefile_id INTEGER NOT NULL,
                domain_name TEXT NOT NULL,
                record_type TEXT NOT NULL,
                ttl INTEGER,
                record_data TEXT,
                FOREIGN KEY (zonefile_id) REFERENCES zonefiles(id)
            )
            ''')
            
            # Create service status table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS service_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                last_run_start TIMESTAMP,
                last_run_end TIMESTAMP,
                status TEXT,
                next_run TIMESTAMP,
                error TEXT
            )
            ''')
            
            self.db_conn.commit()
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Error setting up database: {str(e)}")
            sys.exit(1)
    
    def is_download_window(self):
        """Check if current time is within the zone file download window"""
        if not HAS_PYTZ:
            logger.warning("pytz module not available, using system timezone")
            now = datetime.now()
        else:
            # Convert to the configured timezone
            tz = pytz.timezone(self.timezone)
            now = datetime.now(tz)
        
        # Parse start and end times
        try:
            start_time = datetime.strptime(self.download_start_time, "%H:%M:%S").time()
            end_time = datetime.strptime(self.download_end_time, "%H:%M:%S").time()
            
            # Check if current time is within window
            current_time = now.time()
            return start_time <= current_time <= end_time
            
        except Exception as e:
            logger.error(f"Error parsing time window: {str(e)}")
            return False
    
    def update_service_status(self, status, error=None, next_run=None):
        """Update the service status in the database"""
        try:
            cursor = self.db_conn.cursor()
            now = datetime.now()
            
            if status == 'starting':
                cursor.execute('''
                INSERT INTO service_status 
                (last_run_start, status, error)
                VALUES (?, ?, ?)
                ''', (now, status, error))
                
                self.current_run_id = cursor.lastrowid
                
            elif status in ['completed', 'failed']:
                cursor.execute('''
                UPDATE service_status
                SET last_run_end = ?, status = ?, next_run = ?, error = ?
                WHERE id = ?
                ''', (now, status, next_run, error, self.current_run_id))
            
            self.db_conn.commit()
            
        except Exception as e:
            logger.error(f"Error updating service status: {str(e)}")
    
    def download_and_process_zones(self):
        """Download and process all available zone files"""
        try:
            # Get list of zone links
            access_token = download.authenticate(self.username, self.password, self.authen_base_url)
            
            # Function to get zone links
            def get_zone_links(czds_base_url):
                links_url = czds_base_url + "/czds/downloads/links"
                links_response = download.do_get(links_url, access_token)
                
                status_code = links_response.status_code
                
                if status_code == 200:
                    zone_links = links_response.json()
                    logger.info(f"Found {len(zone_links)} zone files to download")
                    return zone_links
                elif status_code == 401:
                    logger.info("Access token expired, re-authenticating")
                    access_token = download.authenticate(self.username, self.password, self.authen_base_url)
                    return get_zone_links(czds_base_url)
                else:
                    logger.error(f"Failed to get zone links: {status_code}")
                    return None
            
            zone_links = get_zone_links(self.czds_base_url)
            if not zone_links:
                logger.error("Failed to retrieve zone links")
                return False
            
            # Create output directory if needed
            output_dir = os.path.join(self.working_directory, "zonefiles")
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # Process each zone file
            results = {}
            for link in zone_links:
                try:
                    # Extract TLD from the link
                    tld = link.rsplit('/', 1)[-1].split('.')[0]
                    
                    logger.info(f"Processing zone file for TLD: {tld}")
                    
                    # Download the file
                    filename = download.download_one_zone(link, output_dir, self.db_conn)
                    
                    if not filename:
                        logger.warning(f"Failed to download zone file for {tld}")
                        results[tld] = {
                            'status': 'failed',
                            'error': 'Download failed'
                        }
                        continue
                    
                    if not self.change_tracking_enabled:
                        logger.info(f"Change tracking disabled, skipping for {tld}")
                        results[tld] = {
                            'status': 'downloaded',
                            'changes': 0
                        }
                        continue
                    
                    # Get the zonefile ID from the database
                    cursor = self.db_conn.cursor()
                    cursor.execute('''
                    SELECT id, record_count FROM zonefiles
                    WHERE filename = ?
                    ORDER BY download_date DESC
                    LIMIT 1
                    ''', (filename,))
                    
                    row = cursor.fetchone()
                    if not row:
                        logger.warning(f"Zone file {filename} not found in database")
                        results[tld] = {
                            'status': 'failed',
                            'error': 'Zone file not found in database'
                        }
                        continue
                    
                    zonefile_id, record_count = row
                    
                    # Archive the zone file for change tracking
                    self.tracker.archive_zonefile(zonefile_id, filename, tld)
                    
                    # Detect changes
                    changes = self.tracker.detect_changes(tld, zonefile_id)
                    
                    results[tld] = {
                        'status': 'success',
                        'record_count': record_count,
                        'changes': changes
                    }
                    
                    logger.info(f"Successfully processed {tld} zone file with {record_count} records, detected {changes} changes")
                    
                except Exception as e:
                    logger.error(f"Error processing zone file for {tld}: {str(e)}")
                    results[tld] = {
                        'status': 'failed',
                        'error': str(e)
                    }
            
            # Send webhook notifications
            if self.change_tracking_enabled and self.webhooks:
                try:
                    notifications = self.tracker.send_webhook_notifications(self.webhooks)
                    logger.info(f"Sent {notifications} webhook notifications")
                except Exception as e:
                    logger.error(f"Error sending webhook notifications: {str(e)}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error in download and process operation: {str(e)}")
            return False
    
    def scheduler_loop(self):
        """Main scheduler loop that runs in a separate thread"""
        while self.running:
            try:
                # Check if we're in the download window
                if self.is_download_window():
                    logger.info("In download window, starting processing")
                    
                    # Update status
                    self.update_service_status('starting')
                    
                    # Download and process
                    success = self.download_and_process_zones()
                    
                    # Calculate next run time - wait at least 1 hour before checking again
                    next_run = datetime.now() + timedelta(hours=1)
                    
                    # Update final status
                    if success:
                        self.update_service_status('completed', next_run=next_run)
                    else:
                        self.update_service_status('failed', error="Process failed", next_run=next_run)
                
                # Sleep for 15 minutes before checking again
                for _ in range(15 * 60):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Error in scheduler loop: {str(e)}")
                time.sleep(300)  # Wait 5 minutes on error
    
    def start(self):
        """Start the zone service"""
        if self.running:
            logger.warning("Service is already running")
            return
        
        logger.info("Starting CZDS Zone Service")
        self.running = True
        
        # Start the scheduler thread
        self.scheduler_thread = threading.Thread(target=self.scheduler_loop)
        self.scheduler_thread.daemon = True
        self.scheduler_thread.start()
        
        logger.info("Service started successfully")
    
    def stop(self):
        """Stop the zone service"""
        if not self.running:
            logger.warning("Service is not running")
            return
        
        logger.info("Stopping CZDS Zone Service")
        self.running = False
        
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=10)
        
        logger.info("Service stopped successfully")
    
    def run_once(self):
        """Run the download and processing once, regardless of time window"""
        logger.info("Running one-time download and processing")
        
        # Update status
        self.update_service_status('starting')
        
        # Download and process
        success = self.download_and_process_zones()
        
        # Update final status
        if success:
            self.update_service_status('completed')
        else:
            self.update_service_status('failed', error="Process failed")
        
        return success


def main():
    """Main entry point for the service"""
    parser = argparse.ArgumentParser(description='CZDS Zone File Service')
    parser.add_argument('--config', default='config.json', help='Path to configuration file')
    parser.add_argument('--run-once', action='store_true', help='Run once and exit')
    parser.add_argument('--start', action='store_true', help='Start the service')
    parser.add_argument('--stop', action='store_true', help='Stop the service')
    parser.add_argument('--status', action='store_true', help='Check service status')
    
    args = parser.parse_args()
    
    # Create the service
    service = ZoneService(config_path=args.config)
    
    if args.run_once:
        # Run once and exit
        service.run_once()
    elif args.start:
        # Start the service
        service.start()
    elif args.stop:
        # Stop the service
        service.stop()
    elif args.status:
        # Check service status
        cursor = service.db_conn.cursor()
        cursor.execute('''
        SELECT last_run_start, last_run_end, status, next_run, error
        FROM service_status
        ORDER BY id DESC
        LIMIT 1
        ''')
        
        row = cursor.fetchone()
        if row:
            last_start, last_end, status, next_run, error = row
            print(f"Service Status: {status}")
            print(f"Last Run Start: {last_start}")
            print(f"Last Run End: {last_end}")
            print(f"Next Run: {next_run}")
            if error:
                print(f"Error: {error}")
        else:
            print("Service has not been run yet")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()