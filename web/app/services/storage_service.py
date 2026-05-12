import pathlib
import uuid


def get_total_storage_usage_bytes(upload_folder: pathlib.Path) -> int:
    total = 0
    if not upload_folder.exists():
        return total
    for entry in upload_folder.iterdir():
        if entry.is_file():
            total += entry.stat().st_size
    return total


def get_user_storage_usage_bytes(cur, user_id: int, upload_folder: pathlib.Path):
    cur.execute(
        """
        SELECT storage_key
        FROM documents
        WHERE owner_id = %s
        """,
        (user_id,),
    )
    rows = cur.fetchall()
    unique_filenames = {row[0] for row in rows if row and row[0]}
    total = 0
    for filename in unique_filenames:
        file_path = upload_folder / filename
        if file_path.exists() and file_path.is_file():
            total += file_path.stat().st_size
    return len(rows), total


def extract_metadata(filename):
    path = pathlib.Path(filename)
    stats = path.stat()
    return f"size={stats.st_size}, modified={stats.st_mtime}"


def build_storage_key(original_filename: str) -> str:
    extension = pathlib.Path(original_filename).suffix.lower()
    return f"{uuid.uuid4().hex}{extension}"
