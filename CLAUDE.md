# CZDS API Client Python - Claude Guidelines

## Commands
- **Run**: `python download.py` - Runs the zonefile download script
- **Setup**: Make a copy of `config.sample.json` as `config.json` and fill in credentials
- **Environment variable**: Set `CZDS_CONFIG` with JSON config to override config.json
- **Database**: Enable with `"database.enabled": true` in config.json

## Configuration Options
- **database.batch_size**: Number of records per batch (default: 10000)
- **database.max_connections**: Maximum database connections (default: 1)
- **log.interval_seconds**: How often to log progress (default: 5)
- **resume.enabled**: Enable resumable downloads (default: true)
- **resume.processing**: Enable resumable processing (default: true)
- **resume.checkpoint_dir**: Directory for checkpoint files (default: working_directory/checkpoints)

## Code Style
- **Python Version**: Python 3.7+
- **Dependencies**: `requests` library required, `sqlite3` for database features
- **Error Handling**: Use try/except with specific error messages to stderr
- **Naming**: 
  - Snake case for variables and functions (e.g., `download_one_zone`)
  - Descriptive function and variable names
- **Formatting**: 
  - 4-space indentation
  - Use blank lines to separate logical sections
- **Imports**: Standard library imports first, followed by third-party, then local
- **Global Variables**: Minimize use; currently used for configuration and access token
- **HTTP Requests**: Use the helper functions for HTTP operations with proper headers
- **File Structure**: Main logic in download.py with helper functions in separate modules
- **Database**: Use SQLite connections with proper parameterization for all queries

## Large File Processing
- Binary streaming: Process gzip files in binary chunks without full decompression
- Memory efficient: Advanced buffer-based processing for gigabyte-sized files
- Batch processing: Process records in configurable batches
- Database optimization: SQLite WAL mode, proper indexing, transaction batching
- Progress tracking: Regular logging with file position percentage
- Error handling: Skip malformed records without crashing
- Resumability: Checkpoint-based resumption for both downloads and processing

## Zonefile Format
- Standard DNS record format: domain TTL CLASS TYPE data
- Example: virgin. 172800 in soa dns1.nic.virgin. hostmaster.nominet.org.uk.
- CLASS is typically "in" (Internet)
- TYPE can be A, AAAA, MX, SOA, NS, etc.