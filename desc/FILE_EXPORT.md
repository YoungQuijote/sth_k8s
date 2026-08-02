# Kubernetes file export

## Endpoint

```text
POST /api/v1/k8s/files/export
```

The endpoint copies selected regular files from one or more resolved Kubernetes Pods into a service-controlled local export root. It does not use the log cache and does not scan or decompress the exported files.

## Configuration

Service-managed source roots:

```bash
export K8S_FILE_SOURCE_ROOTS_JSON='{"reports":"/opt/app/reports","artifacts":"/data/artifacts"}'
```

A single default source root may also be configured:

```bash
export K8S_FILE_SOURCE_ROOT=/opt/app/reports
```

Default local storage root:

```bash
export K8S_FILE_EXPORT_ROOT=/data/k8s-file-exports
```

Privileged overrides use different tokens:

```bash
export K8S_FILE_SOURCE_ADMIN_TOKEN='source-secret'
export K8S_FILE_STORAGE_ADMIN_TOKEN='storage-secret'
```

- `source.root_dir` requires `K8S_FILE_SOURCE_ADMIN_TOKEN`.
- `destination.storage_root` requires `K8S_FILE_STORAGE_ADMIN_TOKEN`.
- The two tokens are not interchangeable.
- When a token is not configured, that override capability is disabled.

## Request

```json
{
  "ssh": {
    "host": "10.0.0.10",
    "port": 22,
    "username": "root",
    "password": "***"
  },
  "selector": {
    "namespace": "sop",
    "pod": "aico-service",
    "container": "aico"
  },
  "source": {
    "root_key": "reports",
    "mixed_dir_segments": [
      {"mode": "exact", "value": "hsh1"},
      {"mode": "exact", "value": "workspace"},
      {"mode": "exact", "value": "result"},
      {"mode": "exact", "value": "hash2"}
    ],
    "files": [
      {"mode": "exact", "value": "summary.md"},
      {"mode": "exact", "value": "result.json"},
      {"mode": "regex", "value": ".*\\.log$"}
    ]
  },
  "destination": {
    "relative_dir": "job-20260730/hash2",
    "overwrite_policy": "reject"
  },
  "options": {
    "transfer_mode": "compatible",
    "pod_match_policy": "all",
    "max_pods": 32,
    "max_files": 200,
    "max_single_file_size_mb": 2048,
    "max_total_size_mb": 4096,
    "show_details": true,
    "show_decode": "utf-8",
    "show_limit": 32768
  },
  "trace": {}
}
```

`source.files` rules use OR semantics. Files are not recursively discovered.

Every path segment must resolve to exactly one child directory. Multiple matching directories fail rather than silently selecting the newest directory.

## Multi-Pod layout

```text
K8S_FILE_EXPORT_ROOT/
└── relative_dir/
    ├── <pod_identity_hash_1>/
    │   ├── summary.md
    │   └── result.json
    └── <pod_identity_hash_2>/
        ├── summary.md
        └── result.json
```

The Pod directory key is derived from resolved Kubernetes identity:

```text
namespace + pod_uid + container_id + resolved container name
```

It is not derived from the user-provided selector.

## Atomic behavior

The whole request is staged first. Any Pod resolution, transfer, post-transfer stat, file-set, or size mismatch removes the staging directory and fails the request.

`overwrite_policy`:

- `reject` — default; existing destination returns `EXPORT_TARGET_EXISTS`.
- `replace` — build a complete staging directory, then replace the old destination with rollback protection.

## Content preview

When `options.show_details=true`, every response file item contains `content`:

- reads at most the first `show_limit` bytes;
- decodes with `show_decode`;
- invalid byte sequences use replacement characters;
- preview does not modify the exported file.

## Resource boundaries

- `max_pods`: up to 64.
- `max_files`: total across all Pods, up to 2000.
- `max_single_file_size_mb`: hard failure when any selected file is too large.
- `max_total_size_mb`: hard failure before transfer when the aggregate is too large.
- `show_limit`: up to 1 MiB.
- only regular non-symlink files directly under the resolved source directory are selected.
