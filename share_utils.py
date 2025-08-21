import os
import uuid
import json
import shutil

SHARE_DIR = "shared"
SHARE_DATA = os.path.join(SHARE_DIR, "shares.json")


def _ensure_data():
    """Ensure share directory and data file exist."""
    os.makedirs(SHARE_DIR, exist_ok=True)
    if not os.path.exists(SHARE_DATA):
        with open(SHARE_DATA, "w") as f:
            json.dump({}, f)


def load_share_data():
    """Load share metadata from JSON file."""
    _ensure_data()
    with open(SHARE_DATA, "r") as f:
        return json.load(f)


def save_share_data(data):
    """Persist share metadata to JSON file."""
    with open(SHARE_DATA, "w") as f:
        json.dump(data, f)


def create_share(img_path):
    """Create a share entry for an image and return its ID."""
    _ensure_data()
    data = load_share_data()
    share_id = str(uuid.uuid4())
    dest_path = os.path.join(SHARE_DIR, f"{share_id}.png")
    shutil.copy(img_path, dest_path)
    data[share_id] = {"path": dest_path, "count": 0}
    save_share_data(data)
    return share_id


def increment_share(share_id):
    """Increment count for a share and return the image path."""
    data = load_share_data()
    info = data.get(share_id)
    if not info:
        return None
    info["count"] += 1
    save_share_data(data)
    return info["path"]
