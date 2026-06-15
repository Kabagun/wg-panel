import base64
import os
import subprocess

from .core import CLIENTS_DIR, WG_DIR, load_users
from .traffic import remove_device_meta

def client_name(username, device):
    return f"{username}-{device}"

def get_user_devices(username):
    """Return list of device names belonging to a user."""
    os.makedirs(CLIENTS_DIR, exist_ok=True)
    prefix = f"{username}-"
    return sorted([
        f.replace(".conf", "").replace(prefix, "", 1)
        for f in os.listdir(CLIENTS_DIR)
        if f.startswith(prefix) and f.endswith(".conf")
    ])

def get_all_devices():
    """Return list of (username, device, wg_name) tuples for all clients."""
    os.makedirs(CLIENTS_DIR, exist_ok=True)
    users = load_users()
    result = []
    for f in sorted(os.listdir(CLIENTS_DIR)):
        if not f.endswith(".conf"):
            continue
        name = f.replace(".conf", "")
        # Match against known usernames (handles dashes in usernames correctly)
        for username in users:
            prefix = f"{username}-"
            if name.startswith(prefix) and len(name) > len(prefix):
                device = name[len(prefix):]
                result.append((username, device, name))
                break
    return result

def get_config(wg_name):
    path = f"{CLIENTS_DIR}/{wg_name}.conf"
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
    return None

def create_device(wg_name):
    try:
        script = f"{WG_DIR}/add-client.sh"
        r = subprocess.run(
            [script, wg_name],
            capture_output=True, text=True, timeout=30
        )
        return r.returncode == 0, r.stderr
    except Exception as e:
        return False, str(e)

def delete_device(wg_name):
    try:
        script = f"{WG_DIR}/remove-client.sh"
        subprocess.run([script, wg_name], capture_output=True, timeout=15)
    except Exception:
        pass
    path = f"{CLIENTS_DIR}/{wg_name}.conf"
    if os.path.exists(path):
        os.remove(path)
    remove_device_meta(wg_name)

def qr_svg_b64(wg_name):
    path = f"{CLIENTS_DIR}/{wg_name}.conf"
    if not os.path.exists(path):
        return None
    try:
        r = subprocess.run(
            ["qrencode", "-t", "SVG", "-r", path, "-o", "-"],
            capture_output=True, timeout=10
        )
        if r.returncode == 0:
            return "data:image/svg+xml;base64," + base64.b64encode(r.stdout).decode()
    except Exception:
        pass
    return None
