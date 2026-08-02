# Integration snippets

`file_export_models.py` already exists on current `main`; do not recreate it.

## 1. Replace `file_export_rules.py`

Use the `file_export_rules.py` supplied in this bundle.

## 2. Replace `file_export.py`

Use the `file_export.py` supplied in this bundle.

## 3. Add imports to `k8s_log_fetcher_service_main.py`

Place these imports next to the existing `main_loop` / `sqlite_query` imports:

```python
from src.export_tool.file_export import handle_file_export
from src.export_tool.file_export_request import parse_file_export_request
```

## 4. Add the export route

Place this route before the SQLite route:

```python
@app.route("/api/v1/k8s/files/export", methods=["POST"])
def file_export_api():
    req = None
    try:
        payload = request.get_json(force=True, silent=False)
        req = parse_file_export_request(payload)
        return jsonify(handle_file_export(req)), 200
    except ServiceError as se:
        logger.error("File export ServiceError: code={}, message={}", se.code, se.message)
        return jsonify({
            "success": False,
            "export_id": None,
            "destination": None,
            "files": [],
            "meta": {"trace": req.trace if req else {}},
            "warnings": [],
            "error": {
                "code": se.code,
                "message": se.message,
                "details": se.details,
            },
        }), se.http_status
    except Exception as ue:
        logger.exception("File export UnexpectedError: {}", ue)
        return jsonify({
            "success": False,
            "export_id": None,
            "destination": None,
            "files": [],
            "meta": {"trace": req.trace if req else {}},
            "warnings": [],
            "error": {
                "code": "INTERNAL_ERROR",
                "message": str(ue),
                "details": traceback.format_exc(limit=8),
            },
        }), 500
```

## 5. Update service version

In `models.py`:

```diff
-APP_VERSION = "2026.07.20-sqlite-query"
+APP_VERSION = "2026.07.30-file-export"
```

## 6. Run checks

```bash
python -m py_compile \
  file_export_models.py \
  file_export_rules.py \
  file_export_request.py \
  file_transfer.py \
  file_export.py \
  k8s_log_fetcher_service_main.py

python -m unittest -v tests/test_file_export.py
```
