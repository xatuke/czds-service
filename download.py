import json
import sys
import cgi
import os
import gzip
import sqlite3
import requests
import time
import threading
import hashlib
import shutil
import argparse
import datetime as dt
import zlib
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional, Any, Union

try:
    import pytz
    HAS_PYTZ = True
except ImportError:
    HAS_PYTZ = False

from do_authentication import authenticate
from do_http_get import do_get

##############################################################################################################
# First Step: Get the config data from config.json file
##############################################################################################################

try:
    if 'CZDS_CONFIG' in os.environ:
        config_data = os.environ['CZDS_CONFIG']
        config = json.loads(config_data)
    else:
        config_file = open("config.json", "r")
        config = json.load(config_file)
        config_file.close()
except:
    sys.stderr.write("Error loading config.json file.\n")
    exit(1)

# The config.json file must contain the following data:
username = config['icann.account.username']
password = config['icann.account.password']
authen_base_url = config['authentication.base.url']
czds_base_url = config['czds.base.url']

# This is optional. Default to current directory
working_directory = config.get('working.directory', '.') # Default to current directory

# Database configuration (optional)
db_enabled = config.get('database.enabled', False)
db_path = config.get('database.path', os.path.join(working_directory, 'zonefiles.db'))
db_batch_size = config.get('database.batch_size', 10000)
db_max_connections = config.get('database.max_connections', 1)
log_interval_seconds = config.get('log.interval_seconds', 5)
resume_downloads = config.get('resume.enabled', True)
resume_processing = config.get('resume.processing', True)
checkpoint_dir = config.get('resume.checkpoint_dir', os.path.join(working_directory, 'checkpoints'))

# Service configuration (optional)
service_enabled = config.get('service.enabled', False)
service_download_start_time = config.get('service.download_start_time', '00:15:00')
service_download_end_time = config.get('service.download_end_time', '05:45:00')
service_timezone = config.get('service.timezone', 'UTC')
change_tracking_enabled = config.get('service.change_tracking.enabled', True)
archive_dir = config.get('service.change_tracking.archive_dir', os.path.join(working_directory, 'archive'))
webhooks = config.get('webhooks', [])

if not username:
    sys.stderr.write("'icann.account.username' parameter not found in the config.json file\n")
    exit(1)

if not password:
    sys.stderr.write("'icann.account.password' parameter not found in the config.json file\n")
    exit(1)

if not authen_base_url:
    sys.stderr.write("'authentication.base.url' parameter not found in the config.json file\n")
    exit(1)

if not czds_base_url:
    sys.stderr.write("'czds.base.url' parameter not found in the config.json file\n")
    exit(1)



##############################################################################################################
# Second Step: authenticate the user to get an access_token.
# Note that the access_token is global for all the REST API calls afterwards
##############################################################################################################

print("Authenticate user {0}".format(username))
access_token = authenticate(username, password, authen_base_url)



##############################################################################################################
# Third Step: Get the download zone file links
##############################################################################################################

# Function definition for listing the zone links
def get_zone_links(czds_base_url):
    global  access_token

    links_url = czds_base_url + "/czds/downloads/links"
    links_response = do_get(links_url, access_token)

    status_code = links_response.status_code

    if status_code == 200:
        zone_links = links_response.json()
        print("{0}: The number of zone files to be downloaded is {1}".format(datetime.now(), len(zone_links)))
        return zone_links
    elif status_code == 401:
        print("The access_token has been expired. Re-authenticate user {0}".format(username))
        access_token = authenticate(username, password, authen_base_url)
        get_zone_links(czds_base_url)
    else:
        sys.stderr.write("Failed to get zone links from {0} with error code {1}\n".format(links_url, status_code))
        return None


# Get the zone links
zone_links = get_zone_links(czds_base_url)
if not zone_links:
    exit(1)



##############################################################################################################
# Fourth Step: download zone files
##############################################################################################################

# Initialize the database connection and create tables if enabled
def initialize_database():
    if not db_enabled:
        return None
    
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode = WAL")  # Use Write-Ahead Logging for better concurrency
    conn.execute("PRAGMA synchronous = NORMAL")  # Balance between durability and speed
    conn.execute("PRAGMA cache_size = 10000")  # Increase cache size for better performance
    conn.execute("PRAGMA temp_store = MEMORY")  # Store temp tables in memory
    
    cursor = conn.cursor()
    
    # Create tables if they don't exist
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
    
    # Create a table to track download status
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS download_status (
        url TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        last_attempt TIMESTAMP,
        filename TEXT,
        bytes_downloaded INTEGER DEFAULT 0,
        total_bytes INTEGER DEFAULT 0,
        error_message TEXT
    )
    ''')
    
    # Create a table for processing checkpoints
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS processing_checkpoints (
        zonefile_id INTEGER PRIMARY KEY,
        filename TEXT NOT NULL,
        last_processed_line INTEGER DEFAULT 0,
        last_record_count INTEGER DEFAULT 0,
        status TEXT NOT NULL,
        last_updated TIMESTAMP NOT NULL,
        FOREIGN KEY (zonefile_id) REFERENCES zonefiles(id)
    )
    ''')
    
    # Create indexes for common queries
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_dns_records_domain ON dns_records(domain_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_dns_records_type ON dns_records(record_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_dns_records_zonefile ON dns_records(zonefile_id)')
    
    # Create an index on the zonefiles table for the TLD
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_zonefiles_tld ON zonefiles(tld)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_zonefiles_status ON zonefiles(status)')
    
    # Create indexes for the download status table
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_download_status ON download_status(status)')
    
    # Create indexes for the processing checkpoints
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_processing_checkpoints_status ON processing_checkpoints(status)')
    
    conn.commit()
    return conn

# Create checkpoint directory if it doesn't exist
def ensure_checkpoint_dir():
    if not os.path.exists(checkpoint_dir):
        os.makedirs(checkpoint_dir)

# Save checkpoint information for resumability
def save_checkpoint(conn, zonefile_id, filename, line_number, record_count, status):
    if not conn:
        return
    
    cursor = conn.cursor()
    now = datetime.now()
    
    try:
        # Check if checkpoint record exists
        cursor.execute(
            'SELECT 1 FROM processing_checkpoints WHERE zonefile_id = ?', 
            (zonefile_id,)
        )
        
        if cursor.fetchone():
            # Update existing checkpoint
            cursor.execute('''
            UPDATE processing_checkpoints 
            SET last_processed_line = ?, last_record_count = ?, status = ?, last_updated = ?
            WHERE zonefile_id = ?
            ''', (line_number, record_count, status, now, zonefile_id))
        else:
            # Create new checkpoint
            cursor.execute('''
            INSERT INTO processing_checkpoints 
            (zonefile_id, filename, last_processed_line, last_record_count, status, last_updated)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (zonefile_id, filename, line_number, record_count, status, now))
        
        # Also update the zonefile status
        cursor.execute('''
        UPDATE zonefiles
        SET last_processed_line = ?, status = ?
        WHERE id = ?
        ''', (line_number, status, zonefile_id))
        
        conn.commit()
        
        # Also write to a file checkpoint as backup
        if checkpoint_dir:
            ensure_checkpoint_dir()
            checkpoint_file = os.path.join(checkpoint_dir, f"{filename}.checkpoint")
            with open(checkpoint_file, 'w') as f:
                checkpoint_data = {
                    'zonefile_id': zonefile_id,
                    'filename': filename,
                    'line_number': line_number,
                    'record_count': record_count,
                    'status': status,
                    'timestamp': str(now)
                }
                json.dump(checkpoint_data, f)
                
    except Exception as e:
        sys.stderr.write(f"Error saving checkpoint for {filename}: {str(e)}\n")
        # Don't raise exception here to allow processing to continue

# Get the last checkpoint for a file to support resuming
def get_last_checkpoint(conn, filename):
    if not conn:
        return None, 0, 0
    
    cursor = conn.cursor()
    
    try:
        # First check the database
        cursor.execute('''
        SELECT zonefile_id, last_processed_line, last_record_count 
        FROM processing_checkpoints 
        WHERE filename = ? AND status != 'complete'
        ORDER BY last_updated DESC LIMIT 1
        ''', (filename,))
        
        result = cursor.fetchone()
        if result:
            return result
        
        # If not in database, check file checkpoints
        if checkpoint_dir:
            checkpoint_file = os.path.join(checkpoint_dir, f"{filename}.checkpoint")
            if os.path.exists(checkpoint_file):
                with open(checkpoint_file, 'r') as f:
                    checkpoint_data = json.load(f)
                    return (
                        checkpoint_data.get('zonefile_id'),
                        checkpoint_data.get('line_number', 0),
                        checkpoint_data.get('record_count', 0)
                    )
        
        return None, 0, 0
        
    except Exception as e:
        sys.stderr.write(f"Error retrieving checkpoint for {filename}: {str(e)}\n")
        return None, 0, 0

# Generator function to process zonefile line by line with resumability
def process_zonefile(file_path, tld, zonefile_id=None, resume_from_line=0, start_record_count=0):
    """Process a zonefile line by line without loading everything into memory with resumability"""
    batch_size = db_batch_size  # Process in configurable batch sizes
    record_count = start_record_count
    line_number = 0
    last_log_time = datetime.now()
    last_checkpoint_time = datetime.now()
    log_interval = timedelta(seconds=log_interval_seconds)  # Configurable logging interval
    checkpoint_interval = timedelta(seconds=60)  # Save checkpoint every minute
    
    try:
        # Use a custom, streaming-friendly approach to handle gigabyte-sized gzip files
        # Open the gzip file as a binary stream
        with open(file_path, 'rb') as f_in:
            try:
                # Create a streaming decompressor
                decompressor = gzip.GzipFile(fileobj=f_in, mode='rb')
                
                # Create a line iterator that reads efficiently and handles resuming
                records_batch = []
                buffer = b""
                chunk_size = 1024 * 1024  # 1MB chunks for efficient reading
                
                # Skip to the resume point if needed
                if resume_from_line > 0:
                    print(f"{datetime.now()}: Resuming {tld} from line {resume_from_line} with {start_record_count} records already processed")
                    line_number = resume_from_line
                    skipped_lines = 0
                    
                    # Skip lines more efficiently using a buffer approach
                    while skipped_lines < resume_from_line:
                        chunk = decompressor.read(chunk_size)
                        if not chunk:
                            break
                        
                        buffer += chunk
                        lines = buffer.split(b'\n')
                        # Keep the last incomplete line in the buffer
                        buffer = lines[-1]
                        # Process complete lines
                        complete_lines = lines[:-1]
                        skipped_lines += len(complete_lines)
                        
                        # If we skipped too many, rewind by putting excess lines back in buffer
                        if skipped_lines > resume_from_line:
                            excess = skipped_lines - resume_from_line
                            buffer = b'\n'.join(complete_lines[-excess:]) + b'\n' + buffer
                            skipped_lines = resume_from_line
                
                # Process the file line by line without loading everything into memory
                while True:
                    # Read a chunk of compressed data
                    chunk = decompressor.read(chunk_size)
                    if not chunk and not buffer:
                        break
                    
                    buffer += chunk
                    lines = buffer.split(b'\n')
                    
                    # Keep the last potentially incomplete line in the buffer
                    buffer = lines[-1] if chunk else b""
                    
                    # Process complete lines
                    complete_lines = lines[:-1] if chunk else lines
                    
                    for line_bytes in complete_lines:
                        try:
                            line = line_bytes.decode('utf-8', errors='ignore').strip()
                            line_number += 1
                            
                            # Skip empty lines and comments
                            if not line or line.startswith(';'):
                                continue
                            
                            # Basic parsing of zone file records
                            parts = line.split()
                            if len(parts) >= 4:  # DNS records have at least 4 parts: name, ttl, class, type
                                try:
                                    domain_name = parts[0]
                                    ttl = parts[1]
                                    record_class = parts[2].lower()  # typically 'in'
                                    record_type = parts[3].upper()  # A, AAAA, MX, etc.
                                    record_data = ' '.join(parts[4:]) if len(parts) > 4 else ''
                                    
                                    record_count += 1
                                    
                                    # Add to current batch
                                    records_batch.append({
                                        'domain_name': domain_name,
                                        'record_type': record_type,
                                        'ttl': ttl,
                                        'record_data': record_data
                                    })
                                    
                                    # When batch is full, yield it
                                    if len(records_batch) >= batch_size:
                                        yield records_batch, record_count, line_number, 'processing'
                                        records_batch = []
                                    
                                    # Log progress periodically
                                    current_time = datetime.now()
                                    if current_time - last_log_time > log_interval:
                                        # Get file size info
                                        try:
                                            gzip_size = os.path.getsize(file_path)
                                            compressed_pos = f_in.tell()
                                            progress = f"{compressed_pos/gzip_size*100:.1f}% of compressed file" if gzip_size > 0 else ""
                                        except:
                                            progress = ""
                                            
                                        print(f"{current_time}: Processed {record_count:,} records so far from {tld} (line {line_number:,}) {progress}")
                                        last_log_time = current_time
                                    
                                except Exception as e:
                                    # Skip malformed records but don't crash
                                    sys.stderr.write(f"Error parsing record at line {line_number}: {line} - {str(e)}\n")
                                    continue
                        except Exception as e:
                            sys.stderr.write(f"Error processing line {line_number} in {tld}: {str(e)}\n")
                            continue
                    
                    # If we've reached the end of the file, exit the loop
                    if not chunk:
                        break
                
                # Don't forget the last batch if it's not empty
                if records_batch:
                    yield records_batch, record_count, line_number, 'complete'
                else:
                    # If we've already sent all the batches but need to mark as complete
                    yield [], record_count, line_number, 'complete'
            
            except (gzip.BadGzipFile, EOFError, zlib.error) as e:
                # Handle corrupt gzip file specifically
                error_message = f"Error {str(e)} while decompressing data"
                sys.stderr.write(f"Error processing zonefile {tld} at line {line_number}: {error_message}\n")
                # Yield current batch with error status
                if 'records_batch' in locals() and records_batch:
                    yield records_batch, record_count, line_number, 'error'
                # Also update database status to mark file as corrupted
                if db_enabled:
                    cursor = sqlite3.connect(db_path).cursor()
                    cursor.execute(
                        'UPDATE download_status SET status = ?, error_message = ? WHERE filename = ?',
                        ('error', error_message, os.path.basename(file_path))
                    )
                    cursor.connection.commit()
                    cursor.connection.close()
                raise
                
    except Exception as e:
        sys.stderr.write(f"Error processing zonefile {tld} at line {line_number}: {str(e)}\n")
        # Yield current batch with error status so it can be saved
        if 'records_batch' in locals() and records_batch:
            yield records_batch, record_count, line_number, 'error'
        raise

# Save parsed records to the database - with batch processing and resumability
def save_to_database(conn, filename, tld, process_generator):
    if not conn:
        return 0
    
    cursor = conn.cursor()
    start_time = datetime.now()
    
    # Check for existing zonefile record to support resuming
    existing_zonefile_id, resume_line, resume_record_count = get_last_checkpoint(conn, filename)
    
    try:
        # Begin transaction
        conn.execute('BEGIN TRANSACTION')
        
        if existing_zonefile_id:
            # We're resuming an existing zonefile processing
            zonefile_id = existing_zonefile_id
            print(f"{start_time}: Resuming processing of {filename} from line {resume_line} with {resume_record_count} records already processed")
            
            # Check if we need to use the checkpoint directory or regular zonefiles directory
            zonefile_path = os.path.join(checkpoint_dir, 'zonefiles', filename) 
            if not os.path.exists(zonefile_path):
                zonefile_path = os.path.join(working_directory, 'zonefiles', filename)
            
            # Create a generator that starts from the checkpoint
            process_generator = process_zonefile(
                zonefile_path, 
                tld, 
                zonefile_id=zonefile_id, 
                resume_from_line=resume_line, 
                start_record_count=resume_record_count
            )
        else:
            # Insert initial zonefile record with placeholder count and processing status
            cursor.execute('''
            INSERT INTO zonefiles (filename, tld, download_date, record_count, status)
            VALUES (?, ?, ?, ?, ?)
            ''', (filename, tld, start_time, 0, 'processing'))
            
            zonefile_id = cursor.lastrowid
            
            # Create initial checkpoint
            save_checkpoint(conn, zonefile_id, filename, 0, 0, 'processing')
        
        total_records = resume_record_count if existing_zonefile_id else 0
        last_line = resume_line if existing_zonefile_id else 0
        last_status = 'processing'
        last_checkpoint_time = datetime.now()
        checkpoint_interval = timedelta(seconds=30)  # Save checkpoint every 30 seconds
        
        # Process the generator batches
        for records_batch, current_count, line_number, status in process_generator:
            total_records = current_count  # Update the total
            last_line = line_number
            last_status = status
            
            # Only insert if we have records
            if records_batch:
                # Use executemany for batch insertion
                cursor.executemany('''
                INSERT INTO dns_records (zonefile_id, domain_name, record_type, ttl, record_data)
                VALUES (?, ?, ?, ?, ?)
                ''', [
                    (zonefile_id, record['domain_name'], record['record_type'], record['ttl'], record['record_data'])
                    for record in records_batch
                ])
            
            # Check if we should save a checkpoint
            current_time = datetime.now()
            if current_time - last_checkpoint_time > checkpoint_interval:
                save_checkpoint(conn, zonefile_id, filename, line_number, current_count, status)
                last_checkpoint_time = current_time
            
            # Commit intermediate batches to avoid massive transactions
            conn.commit()
            conn.execute('BEGIN TRANSACTION')
        
        # Update the zonefile record with the actual count and final status
        cursor.execute('''
        UPDATE zonefiles SET record_count = ?, status = ? WHERE id = ?
        ''', (total_records, last_status, zonefile_id))
        
        # Save final checkpoint
        save_checkpoint(conn, zonefile_id, filename, last_line, total_records, last_status)
        
        # Also update download status to make sure we reset any "in_progress" status
        if last_status == 'complete':
            cursor.execute('''
            UPDATE download_status
            SET status = 'complete'
            WHERE filename = ?
            ''', (filename,))
        
        # Final commit
        conn.commit()
        
        end_time = datetime.now()
        message = f"{end_time}: Completed database insertion of {total_records} records for {tld}. Time spent: {end_time - start_time}"
        if last_status == 'error':
            message = f"{end_time}: Partially processed {tld} with {total_records} records. Error occurred at line {last_line}."
        
        print(message)
        
    except Exception as e:
        # Roll back transaction on error
        conn.rollback()
        sys.stderr.write(f"Database error for {filename}: {str(e)}\n")
        
        # Update download status to make sure we mark it as error
        try:
            cursor.execute('''
            UPDATE download_status
            SET status = 'error', error_message = ?
            WHERE filename = ?
            ''', (str(e), filename))
            conn.commit()
        except:
            pass
            
        # Save checkpoint on error if we have a zonefile_id
        if 'zonefile_id' in locals():
            try:
                save_checkpoint(conn, zonefile_id, filename, last_line, total_records, 'error')
            except:
                pass
    
    return total_records

# Check if a download has already been attempted and can be resumed
def check_download_status(conn, url):
    if not conn or not resume_downloads:
        return None, None
    
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT status, filename, bytes_downloaded FROM download_status WHERE url = ?', (url,))
        result = cursor.fetchone()
        
        if result:
            status, filename, bytes_downloaded = result
            if status == 'complete':
                # Download already completed
                return 'complete', filename
            elif status == 'in_progress' and bytes_downloaded > 0:
                # Can resume this download
                return 'resume', filename
            elif status == 'error':
                # Retry failed downloads
                print(f"{datetime.now()}: Retrying previously failed download for {url}")
                return None, None
            # Other statuses should restart download
        
        return None, None
        
    except Exception as e:
        sys.stderr.write(f"Error checking download status for {url}: {str(e)}\n")
        return None, None

# Update download status in the database
def update_download_status(conn, url, status, filename=None, bytes_downloaded=0, total_bytes=0, error_message=None):
    if not conn:
        return
    
    cursor = conn.cursor()
    now = datetime.now()
    
    try:
        cursor.execute('SELECT 1 FROM download_status WHERE url = ?', (url,))
        
        if cursor.fetchone():
            # Update existing record
            cursor.execute('''
            UPDATE download_status 
            SET status = ?, last_attempt = ?, filename = ?, 
                bytes_downloaded = ?, total_bytes = ?, error_message = ?
            WHERE url = ?
            ''', (status, now, filename, bytes_downloaded, total_bytes, error_message, url))
        else:
            # Insert new record
            cursor.execute('''
            INSERT INTO download_status 
            (url, status, last_attempt, filename, bytes_downloaded, total_bytes, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (url, status, now, filename, bytes_downloaded, total_bytes, error_message))
        
        conn.commit()
        
    except Exception as e:
        sys.stderr.write(f"Error updating download status for {url}: {str(e)}\n")

# Function definition to download one zone file with resumability
def download_one_zone(url, output_directory, db_conn=None):
    print("{0}: Downloading zone file from {1}".format(str(datetime.now()), url))
    
    # Check if we've already downloaded or can resume this file
    download_status, existing_filename = check_download_status(db_conn, url)
    
    if download_status == 'complete' and existing_filename and resume_downloads:
        print(f"{datetime.now()}: File {existing_filename} already downloaded, skipping")
        return existing_filename
    
    global access_token
    
    # Set up headers for range request if resuming
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'Bearer {access_token}'
    }
    
    # Check if partial file exists and get its size for resume
    bytes_downloaded = 0
    if download_status == 'resume' and existing_filename:
        partial_path = '{0}/{1}'.format(output_directory, existing_filename)
        if os.path.exists(partial_path):
            bytes_downloaded = os.path.getsize(partial_path)
            if bytes_downloaded > 0:
                headers['Range'] = f'bytes={bytes_downloaded}-'
                print(f"{datetime.now()}: Resuming download from byte {bytes_downloaded}")
    
    # Update status to in_progress
    if db_conn:
        update_download_status(db_conn, url, 'in_progress')
    
    # Start or resume download
    download_zone_response = requests.get(url, params=None, headers=headers, stream=True)
    status_code = download_zone_response.status_code
    
    # Handle response
    if status_code in [200, 206]:  # 200 OK or 206 Partial Content
        # Try to get the filename from the header
        _,option = cgi.parse_header(download_zone_response.headers['content-disposition'])
        filename = option.get('filename')

        # If could get a filename from the header, then makeup one like [tld].txt.gz
        if not filename:
            filename = url.rsplit('/', 1)[-1].rsplit('.')[-2] + '.txt.gz'

        # Extract the TLD from the filename
        tld = filename.split('.')[0]
        
        # This is where the zone file will be saved
        path = '{0}/{1}'.format(output_directory, filename)
        
        # Get content length if available
        total_bytes = int(download_zone_response.headers.get('Content-Length', 0)) + bytes_downloaded
        
        # If we're resuming, append to the file; otherwise create a new one
        mode = 'ab' if bytes_downloaded > 0 else 'wb'
        
        try:
            with open(path, mode) as f:
                downloaded_this_session = 0
                start_time = datetime.now()
                last_update_time = datetime.now()
                update_interval = timedelta(seconds=5)
                
                for chunk in download_zone_response.iter_content(8192):  # Larger chunks for better performance
                    if chunk:
                        f.write(chunk)
                        downloaded_this_session += len(chunk)
                        
                        # Update status periodically
                        current_time = datetime.now()
                        if current_time - last_update_time > update_interval:
                            current_total = bytes_downloaded + downloaded_this_session
                            speed = downloaded_this_session / max(1, (current_time - start_time).total_seconds()) / 1024
                            progress = (current_total / total_bytes * 100) if total_bytes > 0 else 0
                            
                            print(f"{current_time}: Downloaded {current_total:,} bytes of {filename} ({progress:.1f}%, {speed:.1f} KB/s)")
                            
                            # Update download status in database
                            if db_conn:
                                update_download_status(
                                    db_conn, url, 'in_progress', filename, 
                                    current_total, total_bytes
                                )
                            
                            last_update_time = current_time
            
            print("{0}: Completed downloading zone to file {1}".format(str(datetime.now()), path))
            
            # Update download status to complete
            if db_conn:
                update_download_status(db_conn, url, 'complete', filename, bytes_downloaded + downloaded_this_session, total_bytes)
            
            # Process the zonefile if database is enabled
            if db_enabled:
                try:
                    process_start_time = datetime.now()
                    print(f"{process_start_time}: Starting memory-efficient processing of {filename}")
                    
                    # Create a generator to process the file
                    # Check for previously interrupted processing
                    existing_zonefile_id, resume_line, resume_record_count = get_last_checkpoint(db_conn, filename)
                    
                    if existing_zonefile_id and resume_processing:
                        generator = process_zonefile(
                            path, tld, 
                            zonefile_id=existing_zonefile_id,
                            resume_from_line=resume_line,
                            start_record_count=resume_record_count
                        )
                    else:
                        generator = process_zonefile(path, tld)
                    
                    # Save to database using the generator
                    total_records = save_to_database(db_conn, filename, tld, generator)
                    
                    process_end_time = datetime.now()
                    print(f"{process_end_time}: Completed processing {total_records} records from {filename}. Time spent: {process_end_time - process_start_time}")
                    
                except Exception as e:
                    sys.stderr.write(f"Error processing zonefile {filename}: {str(e)}\n")
            
            return filename
                
        except Exception as e:
            error_msg = str(e)
            sys.stderr.write(f"Error downloading file {url}: {error_msg}\n")
            
            if db_conn:
                update_download_status(
                    db_conn, url, 'error', filename, 
                    bytes_downloaded + downloaded_this_session, 
                    total_bytes, error_msg
                )

    elif status_code == 401:
        print("The access_token has been expired. Re-authenticate user {0}".format(username))
        access_token = authenticate(username, password, authen_base_url)
        return download_one_zone(url, output_directory, db_conn)
    elif status_code == 404:
        print("No zone file found for {0}".format(url))
        if db_conn:
            update_download_status(db_conn, url, 'not_found', error_message="File not found on server")
    else:
        error_msg = f'Failed to download zone with code {status_code}'
        sys.stderr.write(f'{error_msg} from {url}\n')
        if db_conn:
            update_download_status(db_conn, url, 'error', error_message=error_msg)
    
    return None

# Function definition for downloading all the zone files
def download_zone_files(urls, working_directory):

    # The zone files will be saved in a sub-directory
    output_directory = working_directory + "/zonefiles"

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)
    
    # Initialize database if enabled
    db_conn = None
    if db_enabled:
        print("{0}: Database enabled, initializing database at {1}".format(
            str(datetime.now()), db_path))
        db_conn = initialize_database()
        
        # First check if there are any files in 'error' status that need to be retried
        if db_conn:
            cursor = db_conn.cursor()
            try:
                cursor.execute('''
                SELECT url, filename FROM download_status 
                WHERE status = 'error' OR (status = 'in_progress' AND error_message IS NOT NULL)
                ''')
                error_files = cursor.fetchall()
                
                if error_files:
                    print(f"{datetime.now()}: Found {len(error_files)} previously failed downloads to retry")
                    # Reset their status to allow retrying
                    for url, filename in error_files:
                        cursor.execute('''
                        UPDATE download_status 
                        SET status = NULL, error_message = NULL
                        WHERE url = ?
                        ''', (url,))
                    db_conn.commit()
            except Exception as e:
                sys.stderr.write(f"Error checking for failed downloads: {str(e)}\n")

    # Download the zone files one by one
    for link in urls:
        download_one_zone(link, output_directory, db_conn)
    
    # Close database connection if it was opened
    if db_conn:
        db_conn.close()

# Finally, download all zone files
start_time = datetime.now()
download_zone_files(zone_links, working_directory)
end_time = datetime.now()

print("{0}: DONE DONE. Completed downloading all zone files. Time spent: {1}".format(str(end_time), (end_time-start_time)))
