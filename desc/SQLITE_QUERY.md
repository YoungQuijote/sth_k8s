# Kubernetes SQLite 只读查询

主服务新增接口：

```text
POST /api/v1/k8s/sqlite/query
```

接应服务新增接口：

```text
POST /api/v1/sqlite/rescue/query
```

## 执行模型

1. 主服务通过 SSH 连接池连接 Kubernetes 节点。
2. 根据 `selector` 定位 Pod/container。
3. 根据 `path_segments` 逐层定位目录。
4. `sqlite_file` 在每个 Pod 中必须且只能匹配一个普通文件，符号链接会被跳过。
5. 每个 SQLite source 执行一次 `kubectl exec -i`，容器内启动一次 Python `sqlite3`。
6. 一个只读连接和一个只读事务批量处理全部 `chat_ids`。
7. SSH 不可用或连接池饱和时，主服务调用节点宿主机上的 SQLite 接应接口。

SQLite 文件不会下载到主服务，也不会写入本地缓存。

## 固定 field 查询

`sqlite_rule.py` 中维护服务端规则：

```python
from src.models import SQLiteQuerySpec

SQLITE_QUERY_RULES = {
    "intermediate_state": SQLiteQuerySpec(
        sql="""
        SELECT id, chat_id, content
        FROM intermediate_state
        WHERE chat_id = :chat_id
        ORDER BY id
        """,
        description="查询中间态数据",
    ),
}
```

也可以通过环境变量加载外部 Python 文件：

```text
SQLITE_QUERY_RULES_FILE=/etc/k8s-log-fetcher/sqlite_rules.py
```

规则 SQL 必须包含命名参数 `:chat_id`。

## 自定义 SQL

仅当主服务配置了：

```text
SQLITE_USER_SQL_AUTH_TOKEN=<secret>
```

调用方才可以同时传入：

```json
{
  "user_sql": "SELECT id, content FROM states WHERE chat_id=:chat_id",
  "user_sql_auth": "<secret>"
}
```

`field` 与 `user_sql` 必须二选一。`user_sql_auth` 只在主服务校验，不写日志、不进入 trace，也不会转发给接应服务。

即使鉴权通过，容器内仍强制：

- URI `mode=ro`；
- `PRAGMA query_only=ON`；
- SQLite authorizer 拒绝写入、DDL、`ATTACH/DETACH`、修改型 `PRAGMA` 和扩展加载；
- 单条 `cursor.execute()`，不使用 `executescript()`。

## 请求示例

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
    "pod": "service-name",
    "container": "service-name"
  },
  "path_segments": [
    {"mode": "exact", "value": "opt"},
    {"mode": "exact", "value": "data"}
  ],
  "sqlite_file": {
    "mode": "exact",
    "value": "state.db"
  },
  "chat_ids": ["chat-1", "chat-2"],
  "field": "intermediate_state",
  "result_mode": "columns",
  "columns": ["id", "content"],
  "options": {
    "pod_match_policy": "all",
    "sqlite_busy_timeout_ms": 5000,
    "query_timeout_seconds": 30,
    "max_rows_per_chat_id": 1000,
    "max_total_rows": 5000,
    "max_result_size_bytes": 16777216
  }
}
```

## 返回格式

```json
{
  "success": true,
  "items": [
    {
      "chat_id": "chat-1",
      "source_count": 1,
      "row_count": 2,
      "sources": [
        {
          "source_id": "...",
          "pod": "service-name-xxx",
          "container": "service-name",
          "sqlite_path": "/opt/data/state.db",
          "columns": ["id", "content"],
          "rows": [[1, "value-a"], [2, "value-b"]],
          "row_count": 2
        }
      ]
    }
  ],
  "missed_chat_ids": [],
  "meta": {
    "mode": "remote_sqlite",
    "query_source": "field",
    "pod_count": 1,
    "total_rows": 2
  },
  "warnings": [],
  "error": null
}
```

SQLite `BLOB` 使用以下 JSON envelope：

```json
{"__type__": "bytes", "encoding": "base64", "data": "AAEC"}
```

## 结果模式

- `result_mode="all"`：返回 SQL 结果中的全部列，`columns` 必须为空。
- `result_mode="columns"`：只返回 `columns` 指定的结果列。裁剪发生在 SQL 执行后，不会将列名拼入 SQL。

## 主服务并发参数

```text
SQLITE_SOURCE_MAX_CONCURRENCY=2
SQLITE_SOURCE_MAX_WAITERS=100
SQLITE_SOURCE_ACQUIRE_TIMEOUT_SECONDS=30
```

这些限制是单进程状态；当前仍建议使用单 Gunicorn worker。

## 接应服务安装

将下列文件与原 `k8s_log_rescue_service.py` 放在同一目录：

```text
preset_scripts.py
sqlite_rescue.py
sqlite_rescue_runtime.py
sqlite_rescue_kube.py
```

然后在原接应服务创建 Flask app 后注册扩展：

```python
from src.rescue_channel.rescue_channel import register_sqlite_rescue

register_sqlite_rescue(app)
```

仓库中的 `k8s_log_rescue_service_sqlite.patch` 可直接应用到用户提供的接应服务源码。

## 接应服务参数

```text
LOG_RESCUE_MAX_CONCURRENT_SQLITE_QUERIES=4
LOG_RESCUE_SQLITE_SOURCE_MAX_CONCURRENCY=2
LOG_RESCUE_SQLITE_SOURCE_MAX_WAITERS=100
LOG_RESCUE_SQLITE_SOURCE_ACQUIRE_TIMEOUT_SECONDS=30
```

接应接口继续使用 `LOG_RESCUE_TOKEN` / `X-Rescue-Token`、节点范围、selector allowlist 和 container root 策略。
