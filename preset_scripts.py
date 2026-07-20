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
