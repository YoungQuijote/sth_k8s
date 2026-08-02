# SSH connection pool

The log fetcher now leases exclusive SSH connections from a process-local pool instead of opening and closing one connection for every request.

## Runtime model

- One physical Paramiko connection is leased to only one request at a time.
- Idle connections are reused for requests with the same `host + port + username + credential` identity.
- Credentials are represented in the pool key by a SHA-256 digest and are not logged.
- Connection creation for the same target is serialized.
- Requests wait when the global or per-target connection limit is reached.
- Queue saturation and acquire timeout use the existing kubectl rescue channel.
- Idle, unhealthy, or over-lifetime connections are closed automatically.

## Environment variables

| Variable | Default | Meaning |
| --- | ---: | --- |
| `SSH_POOL_GLOBAL_MAX_CONNECTIONS` | `32` | Maximum physical SSH connections in this process |
| `SSH_POOL_TARGET_MAX_CONNECTIONS` | `4` | Maximum connections for one SSH identity |
| `SSH_POOL_MAX_WAITERS` | `100` | Maximum requests waiting for a connection |
| `SSH_POOL_ACQUIRE_TIMEOUT_SECONDS` | `30` | Maximum wait time for one request |
| `SSH_POOL_IDLE_TIMEOUT_SECONDS` | `30` | Close an unused connection after this duration |
| `SSH_POOL_MAX_LIFETIME_SECONDS` | `600` | Maximum lifetime of a physical connection |
| `SSH_POOL_CONNECT_FAILURE_COOLDOWN_SECONDS` | `5` | Reuse an initial connection failure briefly instead of reconnecting immediately |
| `SSH_POOL_REAPER_INTERVAL_SECONDS` | `5` | Idle connection cleanup interval |

## Deployment boundary

The pool is process-local. Use one Gunicorn worker for now, for example:

```bash
gunicorn \
  --workers 1 \
  --worker-class gthread \
  --threads 16 \
  --bind 0.0.0.0:38575 \
  k8s_log_fetcher_service_main:app
```

With multiple workers, every worker creates an independent pool and the real connection limit is multiplied by the worker count.
