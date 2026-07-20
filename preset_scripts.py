# -----------------------------------------------------------------------------
# 预置脚本
# -----------------------------------------------------------------------------
REAL_TIME_ZIP_TAIL_SCRIPT = r'''
import sys
import zipfile

zip_path = sys.argv[1]
tail_bytes = int(sys.argv[2])
max_entries = int(sys.argv[3])
max_total_uncompressed = int(sys.argv[4])

def is_interesting_member(name: str) -> bool:
    lower = name.lower()
    return lower.endswith(".log") or lower.endswith(".txt") or "log" in lower

def read_member_tail(zf, info, limit: int) -> bytes:
    buf = bytearray()
    with zf.open(info, "r") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > limit:
                del buf[:-limit]
    return bytes(buf)

with zipfile.ZipFile(zip_path, "r") as zf:
    infos = [
        info for info in zf.infolist()
        if not info.is_dir()
        and not info.filename.startswith("/")
        and ".." not in info.filename.split("/")
        and is_interesting_member(info.filename)
    ]
    infos.sort(key=lambda x: (x.date_time, x.filename), reverse=True)
    total_uncompressed = 0
    emitted = 0
    budget = tail_bytes
    for info in infos[:max_entries]:
        total_uncompressed += int(info.file_size)
        if max_total_uncompressed > 0 and total_uncompressed > max_total_uncompressed:
            break
        if budget <= 0:
            break
        member_tail_limit = min(tail_bytes, budget)
        data = read_member_tail(zf, info, member_tail_limit)
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.write(("__ZIP_MEMBER__ " + info.filename + "\n").encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(data)
        if not data.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
        emitted += len(data)
        budget = max(0, tail_bytes - emitted)
'''


SQLITE_QUERY_RESULT_MARKER = "__SQLITE_QUERY_RESULT__="

# stdin: JSON 查询载荷；argv[1]: SQLite 绝对路径。
SQLITE_QUERY_SCRIPT = r'''
import base64
import json
import sqlite3
import sys
import time
import urllib.parse

MARKER = "__SQLITE_QUERY_RESULT__="

class QueryError(RuntimeError):
    def __init__(self, code, message, details=None):
        self.code = code
        self.message = message
        self.details = details
        super().__init__(message)

def emit(payload):
    sys.stdout.write(MARKER)
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.write("\n")
    sys.stdout.flush()

def fail(code, message, details=None):
    emit({"success": False, "error": {"code": code, "message": message, "details": details}})

def cell_size(value):
    if value is None:
        return 4
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    return len(str(value).encode("utf-8"))

def convert_cell(value, max_cell_size):
    size = cell_size(value)
    if size > max_cell_size:
        raise QueryError(
            "SQLITE_CELL_SIZE_LIMIT_EXCEEDED",
            "sqlite result cell exceeded max_cell_size_bytes",
            {"cell_size": size, "limit": max_cell_size},
        )
    if isinstance(value, bytes):
        return {
            "__type__": "bytes",
            "encoding": "base64",
            "data": base64.b64encode(value).decode("ascii"),
        }
    return value

def main():
    if len(sys.argv) != 2:
        raise QueryError("SQLITE_SCRIPT_INPUT_INVALID", "sqlite database path argument is required")
    database_path = sys.argv[1]
    try:
        payload = json.load(sys.stdin)
    except Exception as exc:
        raise QueryError("SQLITE_SCRIPT_INPUT_INVALID", "cannot parse stdin JSON", str(exc)) from exc

    sql = payload.get("sql")
    chat_ids = payload.get("chat_ids")
    result_mode = payload.get("result_mode", "all")
    requested_columns = payload.get("columns") or []
    limits = payload.get("limits") or {}
    busy_timeout_ms = int(payload.get("sqlite_busy_timeout_ms", 5000))
    timeout_seconds = float(payload.get("query_timeout_seconds", 30))

    if not isinstance(sql, str) or not sql.strip():
        raise QueryError("SQLITE_SCRIPT_INPUT_INVALID", "sql must be non-empty string")
    if not isinstance(chat_ids, list) or not all(isinstance(item, str) and item for item in chat_ids):
        raise QueryError("SQLITE_SCRIPT_INPUT_INVALID", "chat_ids must be list[str]")
    if result_mode not in {"all", "columns"}:
        raise QueryError("SQLITE_SCRIPT_INPUT_INVALID", "unsupported result_mode")
    if result_mode == "columns" and (
        not isinstance(requested_columns, list)
        or not requested_columns
        or not all(isinstance(item, str) and item for item in requested_columns)
    ):
        raise QueryError("SQLITE_SCRIPT_INPUT_INVALID", "columns mode requires non-empty columns")

    max_rows_per_chat_id = int(limits["max_rows_per_chat_id"])
    max_total_rows = int(limits["max_total_rows"])
    max_result_size = int(limits["max_result_size_bytes"])
    max_cell_size = int(limits["max_cell_size_bytes"])
    deadline = time.monotonic() + timeout_seconds
    timed_out = [False]

    def progress_handler():
        if time.monotonic() > deadline:
            timed_out[0] = True
            return 1
        return 0

    encoded_path = urllib.parse.quote(database_path, safe="/")
    uri = "file:" + encoded_path + "?mode=ro"
    connection = sqlite3.connect(
        uri,
        uri=True,
        timeout=max(0.001, busy_timeout_ms / 1000.0),
        isolation_level=None,
    )
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = %d" % busy_timeout_ms)
        connection.execute("BEGIN")

        denied = {
            getattr(sqlite3, name)
            for name in (
                "SQLITE_INSERT", "SQLITE_UPDATE", "SQLITE_DELETE",
                "SQLITE_CREATE_INDEX", "SQLITE_CREATE_TABLE", "SQLITE_CREATE_TEMP_INDEX",
                "SQLITE_CREATE_TEMP_TABLE", "SQLITE_CREATE_TEMP_TRIGGER", "SQLITE_CREATE_TEMP_VIEW",
                "SQLITE_CREATE_TRIGGER", "SQLITE_CREATE_VIEW", "SQLITE_DROP_INDEX",
                "SQLITE_DROP_TABLE", "SQLITE_DROP_TEMP_INDEX", "SQLITE_DROP_TEMP_TABLE",
                "SQLITE_DROP_TEMP_TRIGGER", "SQLITE_DROP_TEMP_VIEW", "SQLITE_DROP_TRIGGER",
                "SQLITE_DROP_VIEW", "SQLITE_ALTER_TABLE", "SQLITE_REINDEX", "SQLITE_ANALYZE",
                "SQLITE_PRAGMA", "SQLITE_ATTACH", "SQLITE_DETACH", "SQLITE_TRANSACTION",
                "SQLITE_SAVEPOINT",
            )
            if hasattr(sqlite3, name)
        }

        function_action = getattr(sqlite3, "SQLITE_FUNCTION", -1)
        def authorizer(action, arg1, arg2, database_name, trigger_name):
            if action in denied:
                return sqlite3.SQLITE_DENY
            if action == function_action:
                function_name = (arg2 or arg1 or "").lower()
                if function_name == "load_extension":
                    return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        connection.set_authorizer(authorizer)
        connection.set_progress_handler(progress_handler, 1000)

        items = []
        total_rows = 0
        result_size = 0
        for chat_id in chat_ids:
            if time.monotonic() > deadline:
                raise QueryError("SQLITE_QUERY_TIMEOUT", "sqlite query batch exceeded query_timeout_seconds")

            cursor = connection.execute(sql, {"chat_id": chat_id})
            source_columns = [str(item[0]) for item in (cursor.description or [])]
            if result_mode == "columns":
                positions = []
                for requested in requested_columns:
                    hits = [index for index, name in enumerate(source_columns) if name == requested]
                    if not hits:
                        raise QueryError(
                            "SQLITE_RESULT_COLUMN_NOT_FOUND",
                            "requested result column was not returned by SQL",
                            {"column": requested, "available_columns": source_columns},
                        )
                    if len(hits) > 1:
                        raise QueryError(
                            "SQLITE_RESULT_COLUMN_AMBIGUOUS",
                            "requested result column is ambiguous",
                            {"column": requested, "available_columns": source_columns},
                        )
                    positions.append(hits[0])
                output_columns = list(requested_columns)
            else:
                positions = list(range(len(source_columns)))
                output_columns = source_columns

            rows = []
            row_count = 0
            while True:
                batch = cursor.fetchmany(100)
                if not batch:
                    break
                for raw_row in batch:
                    row_count += 1
                    total_rows += 1
                    if row_count > max_rows_per_chat_id:
                        raise QueryError(
                            "SQLITE_ROWS_LIMIT_EXCEEDED",
                            "rows for one chat_id exceeded max_rows_per_chat_id",
                            {"chat_id": chat_id, "limit": max_rows_per_chat_id},
                        )
                    if total_rows > max_total_rows:
                        raise QueryError(
                            "SQLITE_ROWS_LIMIT_EXCEEDED",
                            "sqlite batch exceeded max_total_rows",
                            {"limit": max_total_rows},
                        )
                    row = [convert_cell(raw_row[index], max_cell_size) for index in positions]
                    result_size += len(
                        json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                    )
                    if result_size > max_result_size:
                        raise QueryError(
                            "SQLITE_RESULT_SIZE_LIMIT_EXCEEDED",
                            "sqlite query result exceeded max_result_size_bytes",
                            {"limit": max_result_size},
                        )
                    rows.append(row)

            items.append({
                "chat_id": chat_id,
                "columns": output_columns,
                "rows": rows,
                "row_count": row_count,
            })

        result = {"success": True, "items": items, "total_rows": total_rows, "error": None}
        encoded_result = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded_result) > max_result_size:
            raise QueryError(
                "SQLITE_RESULT_SIZE_LIMIT_EXCEEDED",
                "sqlite query result exceeded max_result_size_bytes",
                {"limit": max_result_size},
            )
        emit(result)
    finally:
        try:
            connection.rollback()
        except Exception:
            pass
        connection.close()

try:
    main()
except QueryError as exc:
    fail(exc.code, exc.message, exc.details)
except sqlite3.OperationalError as exc:
    message = str(exc)
    lower = message.lower()
    if "locked" in lower or "busy" in lower:
        fail("SQLITE_BUSY_TIMEOUT", message)
    elif "interrupted" in lower:
        fail("SQLITE_QUERY_TIMEOUT", message)
    else:
        fail("SQLITE_QUERY_FAILED", message)
except sqlite3.DatabaseError as exc:
    fail("SQLITE_DATABASE_INVALID", str(exc))
except Exception as exc:
    fail("SQLITE_QUERY_FAILED", str(exc))
'''
