CZDS API Client in Python
===========

This repository provides a Python example of how to download zone files via CZDS (Centralized Zone Data Service) REST API. 
A detail API Specs can be found [here.](https://github.com/icann/czds-api-client-java/tree/master/docs)

There is also an example provided in Java. It can be found in [this repo.](https://github.com/icann/czds-api-client-java)

Installation
------------

This script requires Python 3. It has been tested with Python 3.7.1. 

It requires the `requests` extension library. Please checkout here to see how to install it - https://github.com/requests/requests

Run
---------------------

1. Make a copy of the `config.sample.json` file and name it `config.json`
2. Edit `config.json` and fill in your information
3. Run `python download.py` to download zonefiles manually

For using the automated service:

```bash
# Start the service - runs in background
python zone_service.py --start

# Check the service status
python zone_service.py --status

# Run once immediately (regardless of time window)
python zone_service.py --run-once

# Stop the service
python zone_service.py --stop
```

All the zone files will be saved in `working-directory`/zonefiles, `working-directory` is specified in `config.json`, 
or default to current directory if not specified in `config.json`

Database Integration, Change Tracking and Webhook Notifications
------------------------------------------------------------------

This client now supports extracting zone file data, tracking changes, and sending webhook notifications with memory-efficient processing for large zonefiles and robust resumability:

1. Set `database.enabled` to `true` in your `config.json` file
2. Optionally configure these additional parameters:
   - `database.path`: Custom path for the SQLite database
   - `database.batch_size`: Number of records to process in each batch (default: 10000)
   - `database.max_connections`: Maximum number of database connections (default: 1)
   - `log.interval_seconds`: How often to log progress updates (default: 5)
   - `resume.enabled`: Enable resumable downloads (default: true)
   - `resume.processing`: Enable resumable processing (default: true)
   - `resume.checkpoint_dir`: Directory for checkpoint files (default: working_directory/checkpoints)

3. To enable automated service that tracks changes and sends webhooks:
   - `service.enabled`: Enable the automated zonefile service (default: false)
   - `service.download_start_time`: Start of download window (default: "00:15:00" UTC)
   - `service.download_end_time`: End of download window (default: "05:45:00" UTC)
   - `service.timezone`: Timezone for the download window (default: "UTC")
   - `service.change_tracking.enabled`: Enable change tracking (default: true)
   - Configure `webhooks` array with endpoints to receive notifications

4. When you run the script or service, it will:
   - Download the zone files (resuming interrupted downloads if applicable)
   - Stream and process each zonefile line-by-line without loading it entirely into memory
   - Insert records in efficient batches with optimized transactions
   - Create checkpoints to enable resuming processing in case of failure
   - Track changes between different versions of zonefiles
   - Send webhook notifications about new, changed, or deleted domains
   - Provide regular progress updates during processing
   - Log the processing status

The database contains several tables with performance-optimized indexes:
- `zonefiles`: Stores metadata about each downloaded zone file
- `dns_records`: Stores individual DNS records extracted from the zone files
- `download_status`: Tracks download progress for resumability
- `processing_checkpoints`: Records processing progress for resumability
- `domain_states`: Tracks each domain's current state for change detection
- `change_events`: Records detected changes (new, modified, or deleted domains)
- `service_status`: Tracks automated service runs and statuses

Performance Optimizations:
- **True Streaming**: Files are processed in binary chunks without decompressing the entire file at once
- **Memory Efficiency**: Advanced buffering approach to handle multi-gigabyte files with minimal memory
- **Batch Processing**: Records are processed in configurable batches to optimize memory usage
- **Database Optimization**: Uses SQLite's WAL mode, optimized settings, and proper indexing
- **Progress Tracking**: Regular status updates including file processing percentage
- **Error Handling**: Robust error handling to process partial files and skip malformed records
- **Domain Change Detection**: Efficiently tracks changes between zonefile versions using SHA-256 hashing

Resumability Features:
- **Download Resumption**: Automatically resumes interrupted downloads from the last byte received
- **Processing Resumption**: Restarts processing from the last successfully processed line
- **Checkpoint System**: Creates both database and file-based checkpoints for redundancy
- **Status Tracking**: Maintains detailed status information about each download and processing job
- **Error Recovery**: Can recover from network errors, application crashes, or system failures

Service Capabilities:
- **Scheduled Downloads**: Automatically downloads zonefiles during ICANN's update window (00:00-06:00 UTC)
- **Change Detection**: Efficiently identifies new, modified, and deleted domains across versions
- **Webhook Notifications**: Sends notifications about changes to configured endpoints
- **Filtering**: Supports filtering notifications by TLD and event type
- **Batching**: Configurable batch sizes for webhook notifications
- **Archiving**: Maintains archives of zonefile versions for comparison
- **Command-line Control**: Start, stop, check status, or run once using command-line interface

Documentation
-------------

* CZDS REST API Specs - https://github.com/icann/czds-api-client-java/blob/master/docs/ICANN_CZDS_api.pdf

Contributing
------------

Contributions are welcome.

Other
-----

Reference Implementation in Java: https://github.com/icann/czds-api-client-java