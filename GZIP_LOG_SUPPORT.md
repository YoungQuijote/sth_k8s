# GZIP log support

The log fetcher supports single-file GZIP logs such as:

```text
application.ndjson.gz
run.log.gz
service.txt.gzip
```

This extends the existing ZIP/plain-text scanner without changing its request model.

## Request example

```json
{
  "log_file": {
    "mode": "regex",
    "value": ".*\\.(?:log|ndjson)(?:\\.gz)?$"
  },
  "options": {
    "max_single_file_size_mb": 2048,
    "max_zip_uncompressed_size_mb": 4096
  }
}
```

To scan plain logs, ZIP files, and GZIP files during migration:

```json
{
  "log_file": {
    "mode": "regex",
    "value": ".*\\.(?:log|ndjson|zip|gz|gzip)$"
  }
}
```

## Cached/local scan mode

For the normal cached workflow:

1. the compressed file is copied into the existing request cache;
2. local GZIP files are detected by the `1f 8b` magic number, not only by the suffix;
3. the single GZIP stream is decompressed into the existing `zip_extract` cache area;
4. the decompressed result is keyed by archive path, size, and mtime;
5. repeated scans reuse the decompressed file;
6. TTL and size cleanup reuse `zip_extract_cache_ttl_seconds` and `zip_extract_cache_max_size_mb`.

`max_zip_uncompressed_size_mb` is also the hard maximum decompressed size for one GZIP stream. The existing option name is retained for backward compatibility.

## Real-time remote scan mode

When `options.real_time=true`, the target container runs a Python standard-library GZIP reader:

- the complete decompressed file is not written to container disk;
- compressed data is decompressed sequentially;
- only the final `real_tail_bytes` of decompressed data are retained;
- decompressed bytes are limited by `max_zip_uncompressed_size_mb`;
- the resulting text is scanned by the existing reverse line/regex pipeline.

The target container must provide:

```text
python3
Python standard-library gzip
```

## Boundaries

- Supported: a single log/text/NDJSON stream compressed as `.gz` or `.gzip`.
- Not supported by this change: `.tar.gz`, `.tgz`, or other tar archives wrapped in GZIP.
- Invalid, truncated, or oversized streams are skipped or returned as explicit GZIP errors.
- ZIP behavior remains unchanged.
- The separately deployed log rescue service is not stored in this repository; it must receive the equivalent GZIP reader change before GZIP requests can fall back through that channel.

## Error and warning codes

Cached/local mode:

```text
GZIP_TOO_LARGE
GZIP_DECOMPRESS_FAILED
GZIP_TAR_ARCHIVE_NOT_SUPPORTED
GZIP_CACHE_META_UPDATE_RACE
GZIP_CACHE_META_UPDATE_FAILED
GZIP_CACHE_GC_FAILED
```

Real-time mode:

```text
REAL_TIME_GZIP_TOO_LARGE
REAL_TIME_GZIP_INVALID
REAL_TIME_GZIP_READER_NOT_AVAILABLE
REAL_TIME_GZIP_TAIL_FAILED
REAL_TIME_GZIP_TAR_ARCHIVE_NOT_SUPPORTED
```
