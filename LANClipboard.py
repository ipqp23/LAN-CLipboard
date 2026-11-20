"""
LAN Clipboard - Version 0.5
Windows LAN discovery, TightVNC session detection, GUI, tray, startup toggle
and FILE + TEXT CLIPBOARD TRANSFER.

How it works:
    Run LAN Clipboard on BOTH computers (the one you control and the one being
    controlled). When a TightVNC session between them is detected, copying
    files (Ctrl+C in Explorer) on either PC sends them over the LAN to the
    other PC and puts them on its clipboard, ready for Ctrl+V.

Requirements:
    py -m pip install psutil pystray pillow

Run:
    py LANClipboard.py

Notes:
    - Discovery uses UDP broadcast port 50556.
    - File transfer uses TCP port 50555 (allow it in Windows Firewall, Private network).
    - Received files go to a temporary folder (%TEMP%\\LANClipboard) and are deleted once they are
      no longer on the clipboard (and when the app closes), so nothing piles up.
    - On the very first run the app asks Windows once to open its firewall ports.
    - Transfers are only accepted from a PC with an active TightVNC session
      to this one. Traffic is NOT encrypted - use on a trusted LAN only.
    - Copied text (Ctrl+C anywhere) is synced too, independent of TightVNC's own clipboard
      option. Text copied from password managers (which mark it as private) is skipped.
      Text is sent unencrypted like files, so untick 'Sync copied text' if that worries you.
    - Run the SAME version on both PCs.
    - UDP discovery is optional. The partner is also found straight from the TightVNC
      connection and checked on TCP 50555, so it works over Tailscale, other VPNs or any
      routed network (whatever IP your VNC viewer connects to is the IP that gets used).
"""

import ctypes
import json
import os
import queue
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
from collections import deque
from datetime import datetime
from pathlib import Path

try:
    import psutil
except ImportError:
    raise SystemExit("Missing dependency: psutil\nInstall with: py -m pip install psutil")

try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError:
    raise SystemExit("Missing tray dependencies.\nInstall with: py -m pip install pystray pillow")

if os.name == "nt":
    import winreg
else:
    winreg = None


APP_NAME = "LAN Clipboard"
APP_VERSION = "0.5"
DISCOVERY_PORT = 50556
TRANSFER_PORT = 50555
BROADCAST_INTERVAL = 3.0
PEER_TIMEOUT = 12.0
VNC_PORTS = set(range(5900, 5910))
STARTUP_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
STARTUP_VALUE = "LANClipboard"

CHUNK = 256 * 1024
CLIPBOARD_POLL = 0.4
MAX_ENTRIES = 20000
MAX_TOTAL_BYTES = 10 * 1024 ** 3          # refuse transfers larger than 10 GiB
FREE_SPACE_MARGIN = 200 * 1024 ** 2       # keep 200 MiB free after receiving
INBOX_DIR = Path(tempfile.gettempdir()) / "LANClipboard"
STATE_DIR = Path(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()) / "LANClipboard"
FIREWALL_FLAG = STATE_DIR / "firewall_prompted"
CLEANUP_DELAY = 30  # seconds to wait before deleting received files that left the clipboard
CF_HDROP = 15
CF_UNICODETEXT = 13
MAX_TEXT_CHARS = 1_000_000
GMEM_MOVEABLE = 0x0002
GMEM_ZEROINIT = 0x0040


def now_text():
    return datetime.now().strftime("%H:%M:%S")


def local_ip_for(target_ip="8.8.8.8"):
    """Find the local interface IP used for routing; no packets are sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 80))
        return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
    finally:
        s.close()


def get_startup_command():
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --minimized'
    script = os.path.abspath(sys.argv[0])
    return f'"{sys.executable}" "{script}" --minimized'


def startup_is_enabled():
    if os.name != "nt":
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_KEY, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, STARTUP_VALUE)
            return True
    except OSError:
        return False


def set_startup_enabled(enabled):
    if os.name != "nt":
        raise RuntimeError("Windows startup integration is available on Windows only.")
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, STARTUP_KEY, 0, winreg.KEY_SET_VALUE
    ) as key:
        if enabled:
            winreg.SetValueEx(key, STARTUP_VALUE, 0, winreg.REG_SZ, get_startup_command())
        else:
            try:
                winreg.DeleteValue(key, STARTUP_VALUE)
            except FileNotFoundError:
                pass


# ----------------------------------------------------------------------
# Windows clipboard (CF_HDROP = list of files) through ctypes
# ----------------------------------------------------------------------
if os.name == "nt":
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)

    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.argtypes = []
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.argtypes = []
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
    user32.IsClipboardFormatAvailable.restype = wintypes.BOOL
    user32.GetClipboardData.argtypes = [wintypes.UINT]
    user32.GetClipboardData.restype = wintypes.HANDLE
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    user32.RegisterClipboardFormatW.restype = wintypes.UINT
    user32.GetClipboardSequenceNumber.argtypes = []
    user32.GetClipboardSequenceNumber.restype = wintypes.DWORD

    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = wintypes.LPVOID
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalFree.restype = wintypes.HGLOBAL

    shell32.DragQueryFileW.argtypes = [wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT]
    shell32.DragQueryFileW.restype = wintypes.UINT

    class DROPFILES(ctypes.Structure):
        _fields_ = [
            ("pFiles", wintypes.DWORD),
            ("pt", wintypes.POINT),
            ("fNC", wintypes.BOOL),
            ("fWide", wintypes.BOOL),
        ]


def _open_clipboard(retries=15):
    for _ in range(retries):
        if user32.OpenClipboard(None):
            return True
        time.sleep(0.05)
    return False


def clipboard_sequence():
    return int(user32.GetClipboardSequenceNumber())


def get_clipboard_files():
    """Return the list of file/folder paths currently copied in Explorer."""
    if os.name != "nt" or not user32.IsClipboardFormatAvailable(CF_HDROP):
        return []
    if not _open_clipboard():
        return []
    try:
        handle = user32.GetClipboardData(CF_HDROP)
        if not handle:
            return []
        count = shell32.DragQueryFileW(handle, 0xFFFFFFFF, None, 0)
        paths = []
        for i in range(count):
            length = shell32.DragQueryFileW(handle, i, None, 0)
            buf = ctypes.create_unicode_buffer(length + 1)
            shell32.DragQueryFileW(handle, i, buf, length + 1)
            paths.append(buf.value)
        return paths
    finally:
        user32.CloseClipboard()


def set_clipboard_files(paths):
    """Put files on the clipboard exactly like Explorer's Ctrl+C does."""
    if os.name != "nt" or not paths:
        return False
    data = ("\0".join(paths) + "\0\0").encode("utf-16-le")
    header_size = ctypes.sizeof(DROPFILES)
    hmem = kernel32.GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, header_size + len(data))
    if not hmem:
        return False
    ptr = kernel32.GlobalLock(hmem)
    if not ptr:
        kernel32.GlobalFree(hmem)
        return False
    drop = DROPFILES.from_address(ptr)
    drop.pFiles = header_size
    drop.fWide = 1
    ctypes.memmove(ptr + header_size, data, len(data))
    kernel32.GlobalUnlock(hmem)

    if not _open_clipboard():
        kernel32.GlobalFree(hmem)
        return False
    try:
        user32.EmptyClipboard()
        if not user32.SetClipboardData(CF_HDROP, hmem):
            kernel32.GlobalFree(hmem)
            return False
        return True  # the system owns the memory now
    finally:
        user32.CloseClipboard()


_EXCLUDE_FMT = None


def get_clipboard_text():
    """Return copied text, or None (also None for content marked private, e.g. password managers)."""
    global _EXCLUDE_FMT
    if os.name != "nt" or not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
        return None
    if _EXCLUDE_FMT is None:
        _EXCLUDE_FMT = user32.RegisterClipboardFormatW("ExcludeClipboardContentFromMonitorProcessing")
    if _EXCLUDE_FMT and user32.IsClipboardFormatAvailable(_EXCLUDE_FMT):
        return None
    if not _open_clipboard():
        return None
    try:
        handle = user32.GetClipboardData(CF_UNICODETEXT)
        if not handle:
            return None
        ptr = kernel32.GlobalLock(handle)
        if not ptr:
            return None
        try:
            return ctypes.wstring_at(ptr)
        finally:
            kernel32.GlobalUnlock(handle)
    finally:
        user32.CloseClipboard()


def set_clipboard_text(text):
    if os.name != "nt":
        return False
    data = (text.replace("\0", "") + "\0").encode("utf-16-le")
    hmem = kernel32.GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, len(data))
    if not hmem:
        return False
    ptr = kernel32.GlobalLock(hmem)
    if not ptr:
        kernel32.GlobalFree(hmem)
        return False
    ctypes.memmove(ptr, data, len(data))
    kernel32.GlobalUnlock(hmem)
    if not _open_clipboard():
        kernel32.GlobalFree(hmem)
        return False
    try:
        user32.EmptyClipboard()
        if not user32.SetClipboardData(CF_UNICODETEXT, hmem):
            kernel32.GlobalFree(hmem)
            return False
        return True
    finally:
        user32.CloseClipboard()


# ----------------------------------------------------------------------
# Transfer protocol (TCP): 4-byte length + JSON messages, then raw file bytes
#   sender  -> {"app","version","from","top":[...],"total","files":[{rel,size,dir}]}
#   receiver-> {"ok": true}  or {"ok": false, "reason": "..."}
#   sender  -> raw bytes of every file, in order
#   receiver-> {"done": true}
# ----------------------------------------------------------------------
def fmt_size(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def read_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(CHUNK, n - len(buf)))
        if not chunk:
            raise ConnectionError("Connection closed early")
        buf.extend(chunk)
    return bytes(buf)


def send_msg(sock, obj):
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_msg(sock, limit=16 * 1024 * 1024):
    (length,) = struct.unpack(">I", read_exact(sock, 4))
    if length > limit:
        raise ValueError("Message too large")
    return json.loads(read_exact(sock, length).decode("utf-8"))


def safe_join(base, rel):
    """Join a relative '/'-separated path onto base; refuse anything that escapes it."""
    if not isinstance(rel, str) or not rel:
        raise ValueError("Bad file name")
    parts = rel.split("/")
    for part in parts:
        if part in ("", ".", "..") or any(c in part for c in '\\:*?"<>|') or any(ord(c) < 32 for c in part):
            raise ValueError(f"Unsafe file name: {rel!r}")
    base = os.path.abspath(base)
    dest = os.path.abspath(os.path.join(base, *parts))
    if os.path.commonpath([base, dest]) != base or dest == base:
        raise ValueError(f"Unsafe file path: {rel!r}")
    return dest


def collect_entries(paths):
    """Expand copied files/folders into a flat list of entries to send."""
    entries, top, used, total = [], [], set(), 0
    for p in paths:
        p = os.path.abspath(p)
        name = os.path.basename(p.rstrip("\\/"))
        if not name:
            continue  # drive roots are not supported
        stem, ext = os.path.splitext(name)
        n = 2
        while name.lower() in used:
            name = f"{stem} ({n}){ext}"
            n += 1
        used.add(name.lower())
        if os.path.isdir(p):
            top.append(name)
            entries.append({"rel": name, "size": 0, "dir": True})
            for root, dirs, files in os.walk(p):
                rel_root = os.path.relpath(root, p)
                prefix = name if rel_root == "." else name + "/" + rel_root.replace(os.sep, "/")
                for d in dirs:
                    entries.append({"rel": prefix + "/" + d, "size": 0, "dir": True})
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        size = os.path.getsize(fp)
                    except OSError:
                        continue
                    entries.append({"rel": prefix + "/" + f, "size": size, "dir": False, "src": fp})
                    total += size
        elif os.path.isfile(p):
            top.append(name)
            size = os.path.getsize(p)
            entries.append({"rel": name, "size": size, "dir": False, "src": p})
            total += size
        if len(entries) > MAX_ENTRIES:
            raise ValueError(f"Too many files (limit {MAX_ENTRIES})")
    return top, entries, total


def stream_send(sock, hostname, top, entries, total, progress=None):
    header = {
        "app": "LANClipboard",
        "version": APP_VERSION,
        "from": hostname,
        "top": top,
        "total": total,
        "files": [{k: v for k, v in e.items() if k != "src"} for e in entries],
    }
    send_msg(sock, header)
    reply = recv_msg(sock)
    if not reply.get("ok"):
        raise RuntimeError(reply.get("reason", "Receiver refused the transfer"))
    sent = 0
    for e in entries:
        if e["dir"]:
            continue
        remaining = e["size"]
        with open(e["src"], "rb") as fh:
            while remaining > 0:
                chunk = fh.read(min(CHUNK, remaining))
                if not chunk:
                    raise IOError(f"{e['rel']} changed while sending")
                sock.sendall(chunk)
                remaining -= len(chunk)
                sent += len(chunk)
                if progress:
                    progress(sent, total)
    if not recv_msg(sock).get("done"):
        raise RuntimeError("Receiver did not confirm the transfer")
    if progress:
        progress(total, total)


def stream_send_text(sock, hostname, text):
    send_msg(sock, {"app": "LANClipboard", "version": APP_VERSION, "from": hostname, "kind": "text", "text": text})
    reply = recv_msg(sock)
    if not reply.get("ok"):
        raise RuntimeError(reply.get("reason", "Receiver refused the text"))
    if not recv_msg(sock).get("done"):
        raise RuntimeError("Receiver did not confirm the text")


def stream_ping(sock):
    """Ask a LAN Clipboard receiver to identify itself. Returns its computer name."""
    send_msg(sock, {"app": "LANClipboard", "version": APP_VERSION, "kind": "ping"})
    reply = recv_msg(sock)
    if not reply.get("ok"):
        raise RuntimeError("Ping refused")
    return reply.get("name") or ""


def stream_receive(conn, inbox_dir, reject_reason=None, progress=None, accept_text=True, hostname=""):
    """Receive one transfer. Returns {"kind": "text", "text"} or
    {"kind": "files", "folder", "top_paths", "total", "count"} (files go into a fresh folder)."""
    header = recv_msg(conn)
    if header.get("app") != "LANClipboard":
        raise ValueError("Not a LAN Clipboard sender")
    if header.get("kind") == "ping":
        send_msg(conn, {"ok": True, "name": hostname})
        return {"kind": "ping"}
    if reject_reason:
        send_msg(conn, {"ok": False, "reason": reject_reason})
        raise PermissionError(reject_reason)

    if header.get("kind") == "text":
        text = header.get("text")
        if not accept_text:
            reason = "Text sync is turned off on the receiver"
            send_msg(conn, {"ok": False, "reason": reason})
            raise RuntimeError(reason)
        if not isinstance(text, str) or len(text) > MAX_TEXT_CHARS:
            send_msg(conn, {"ok": False, "reason": "Bad text payload"})
            raise ValueError("Bad text payload")
        send_msg(conn, {"ok": True})
        send_msg(conn, {"done": True})
        return {"kind": "text", "text": text}

    files, top = header.get("files"), header.get("top")
    session_dir = Path(inbox_dir) / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    base = os.path.abspath(session_dir)
    plan, top_paths, total = [], [], 0
    try:
        if not isinstance(files, list) or not isinstance(top, list) or not top or len(files) > MAX_ENTRIES:
            raise ValueError("Malformed transfer header")
        for f in files:
            if not isinstance(f, dict) or not isinstance(f.get("size"), int) or f["size"] < 0:
                raise ValueError("Malformed file entry")
            is_dir = bool(f.get("dir"))
            plan.append((safe_join(base, f.get("rel")), is_dir, 0 if is_dir else f["size"]))
            total += 0 if is_dir else f["size"]
        top_paths = [safe_join(base, name) for name in top]
        if total > MAX_TOTAL_BYTES:
            raise ValueError("Transfer is too large")
        Path(inbox_dir).mkdir(parents=True, exist_ok=True)
        if total + FREE_SPACE_MARGIN > shutil.disk_usage(inbox_dir).free:
            raise ValueError("Not enough free disk space")
    except ValueError as exc:
        send_msg(conn, {"ok": False, "reason": str(exc)})
        raise

    send_msg(conn, {"ok": True})
    os.makedirs(base)
    try:
        received = 0
        for dest, is_dir, size in plan:
            if is_dir:
                os.makedirs(dest, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            remaining = size
            with open(dest, "wb") as out:
                while remaining > 0:
                    chunk = conn.recv(min(CHUNK, remaining))
                    if not chunk:
                        raise ConnectionError("Sender disconnected")
                    out.write(chunk)
                    remaining -= len(chunk)
                    received += len(chunk)
                    if progress:
                        progress(received, total)
        if not all(os.path.exists(p) for p in top_paths):
            raise ValueError("Transfer incomplete")
        send_msg(conn, {"done": True})
    except BaseException:
        shutil.rmtree(base, ignore_errors=True)
        raise
    return {"kind": "files", "folder": base, "top_paths": top_paths, "total": total, "count": len(plan)}


FIREWALL_RULES = ("LAN Clipboard TCP", "LAN Clipboard UDP")


def firewall_rules_exist():
    """True if both LAN Clipboard inbound rules are present (no admin needed to check)."""
    if os.name != "nt":
        return False
    try:
        for rule in FIREWALL_RULES:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule}"],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode != 0 or rule not in result.stdout:
                return False
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def add_firewall_rules_elevated():
    """Ask Windows (UAC prompt) to create the inbound firewall rules. Returns True if launched."""
    if os.name != "nt":
        return False
    command = (
        f"Remove-NetFirewallRule -DisplayName '{FIREWALL_RULES[0]}','{FIREWALL_RULES[1]}' -ErrorAction SilentlyContinue; "
        f"New-NetFirewallRule -DisplayName '{FIREWALL_RULES[0]}' -Direction Inbound -Protocol TCP "
        f"-LocalPort {TRANSFER_PORT} -Action Allow -Profile Any; "
        f"New-NetFirewallRule -DisplayName '{FIREWALL_RULES[1]}' -Direction Inbound -Protocol UDP "
        f"-LocalPort {DISCOVERY_PORT} -Action Allow -Profile Any"
    )
    params = f'-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "{command}"'
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", "powershell.exe", params, None, 0)
    return result > 32


def wipe_inbox():
    """Delete everything in the temporary receive folder."""
    shutil.rmtree(INBOX_DIR, ignore_errors=True)


def path_is_inside(path, folder):
    try:
        path = os.path.normcase(os.path.abspath(path))
        folder = os.path.normcase(os.path.abspath(folder))
        return os.path.commonpath([path, folder]) == folder
    except ValueError:
        return False


def firewall_prompted():
    return FIREWALL_FLAG.exists()


def mark_firewall_prompted():
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        FIREWALL_FLAG.write_text("1")
    except OSError:
        pass


THEME = {
    "bg": "#0f172a",
    "card": "#1e293b",
    "line": "#334155",
    "text": "#e2e8f0",
    "muted": "#94a3b8",
    "faint": "#64748b",
    "accent": "#38bdf8",
    "accent_dark": "#0ea5e9",
    "on_accent": "#04202e",
    "good": "#34d399",
    "warn": "#fbbf24",
    "bad": "#f87171",
    "idle": "#64748b",
    "log_bg": "#0b1220",
    "log_fg": "#cbd5e1",
}


class LANClipboardApp:
    def __init__(self, start_minimized=False):
        self.root = tk.Tk()
        self.root.title(f"{APP_NAME}  •  v{APP_VERSION}")
        self.root.geometry("580x470")
        self.root.minsize(540, 440)
        self.root.configure(bg=THEME["bg"])

        self.stop_event = threading.Event()
        self.ui_queue = queue.Queue()
        self.peers_lock = threading.Lock()
        self.peers = {}
        self.active_partner = None
        self.last_session_signature = None
        self.logs = deque(maxlen=250)
        self.local_ip = local_ip_for()
        self.hostname = socket.gethostname()
        self.instance_id = f"{self.hostname}-{os.getpid()}"

        self.discovery_socket = None
        self.tray_icon = None
        self.tray_thread = None
        self.tray_available = True

        self.partners = []
        self.partner_ips = set()
        self.suppress_until = 0.0
        self.auto_send_enabled = True
        self.text_sync_enabled = True
        self.last_text = ""
        self.probe_cache = {}
        self.current_received = None
        self.pending_delete = []
        self.cleanup_lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.recv_lock = threading.Lock()
        self.server_socket = None

        self._build_ui()
        self._log("Application started.")
        self._log(f"Computer: {self.hostname}  |  LAN IP: {self.local_ip}")
        self._log("Discovery service starting...")

        self.discovery_thread = threading.Thread(target=self._discovery_loop, daemon=True)
        self.discovery_thread.start()

        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

        try:
            wipe_inbox()
        except OSError:
            pass
        self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self.server_thread.start()
        self.clipboard_thread = threading.Thread(target=self._clipboard_loop, daemon=True)
        self.clipboard_thread.start()
        threading.Thread(target=self._check_firewall_on_start, daemon=True).start()

        self.root.protocol("WM_DELETE_WINDOW", self.hide_to_tray)
        self.root.after(150, self._process_ui_queue)
        self.root.after(500, self._start_tray)

        if start_minimized:
            self.root.after(800, self.root.withdraw)

    def _apply_styles(self):
        T = THEME
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        base = ("Segoe UI", 9)

        style.configure("TButton", font=base, padding=(12, 5), background=T["line"], foreground=T["text"],
                        borderwidth=0, focuscolor=T["line"], relief="flat")
        style.map("TButton", background=[("active", "#475569"), ("pressed", "#475569")])
        style.configure("Accent.TButton", background=T["accent_dark"], foreground="#ffffff",
                        font=("Segoe UI", 9, "bold"), focuscolor=T["accent_dark"])
        style.map("Accent.TButton",
                  background=[("active", T["accent"]), ("pressed", T["accent"])],
                  foreground=[("active", T["on_accent"])])
        style.configure("Ghost.TButton", background=T["bg"], foreground=T["muted"], focuscolor=T["bg"], padding=(8, 5))
        style.map("Ghost.TButton",
                  background=[("active", T["card"])],
                  foreground=[("active", T["text"])])

        style.configure("Card.TCheckbutton", background=T["card"], foreground=T["text"], font=base,
                        focuscolor=T["card"], indicatorbackground=T["bg"], indicatorforeground="#ffffff",
                        upperbordercolor=T["line"], lowerbordercolor=T["line"])
        style.map("Card.TCheckbutton",
                  background=[("active", T["card"])],
                  indicatorbackground=[("selected", T["accent_dark"]), ("!selected", T["bg"])])

        style.configure("Dark.TNotebook", background=T["bg"], borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure("Dark.TNotebook.Tab", background=T["bg"], foreground=T["muted"],
                        padding=(8, 5), font=base, borderwidth=0)
        style.map("Dark.TNotebook.Tab",
                  background=[("selected", T["log_bg"])],
                  foreground=[("selected", T["accent"])])

        style.configure("Dark.Treeview", background=T["log_bg"], fieldbackground=T["log_bg"],
                        foreground=T["text"], rowheight=24, borderwidth=0, font=base)
        style.map("Dark.Treeview",
                  background=[("selected", T["line"])],
                  foreground=[("selected", T["text"])])
        style.configure("Dark.Treeview.Heading", background=T["card"], foreground=T["muted"],
                        font=("Segoe UI", 8, "bold"), relief="flat", borderwidth=0)
        style.map("Dark.Treeview.Heading", background=[("active", T["line"])])

        style.configure("Slim.Horizontal.TProgressbar", troughcolor=T["card"], background=T["accent"],
                        bordercolor=T["bg"], lightcolor=T["accent"], darkcolor=T["accent"],
                        thickness=6, borderwidth=0)
        style.configure("Dark.Vertical.TScrollbar", background=T["line"], troughcolor=T["log_bg"],
                        bordercolor=T["log_bg"], arrowcolor=T["muted"], relief="flat", gripcount=0)

    @staticmethod
    def _rounded_rect(canvas, x1, y1, x2, y2, r, **kw):
        points = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
                  x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
        return canvas.create_polygon(points, smooth=True, **kw)

    def _info_cell(self, parent, column, title, variable):
        T = THEME
        cell = tk.Frame(parent, bg=T["card"])
        cell.grid(row=0, column=column, sticky="nsew", padx=12, pady=8)
        tk.Label(cell, text=title, bg=T["card"], fg=T["muted"], font=("Segoe UI", 8, "bold")).pack(anchor="w")
        tk.Label(cell, textvariable=variable, bg=T["card"], fg=T["text"],
                 font=("Segoe UI", 11, "bold"), anchor="w").pack(anchor="w", pady=(2, 0))

    def _build_ui(self):
        T = THEME
        self._apply_styles()

        outer = tk.Frame(self.root, bg=T["bg"])
        outer.pack(fill="both", expand=True, padx=14, pady=12)

        # ---- header: logo, title, live status ----
        header = tk.Frame(outer, bg=T["bg"])
        header.pack(fill="x")
        logo = tk.Canvas(header, width=38, height=38, bg=T["bg"], highlightthickness=0)
        logo.pack(side="left")
        self._rounded_rect(logo, 1, 1, 37, 37, 9, fill=T["accent_dark"], outline="")
        logo.create_rectangle(10, 11, 28, 24, outline="white", width=2)
        logo.create_line(15, 29, 23, 29, fill="white", width=2)
        logo.create_line(19, 24, 19, 29, fill="white", width=2)

        titles = tk.Frame(header, bg=T["bg"])
        titles.pack(side="left", padx=(10, 0))
        tk.Label(titles, text="LAN Clipboard", bg=T["bg"], fg=T["text"],
                 font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tk.Label(titles, text=f"Files & text for TightVNC  \u00b7  v{APP_VERSION}", bg=T["bg"], fg=T["muted"],
                 font=("Segoe UI", 8)).pack(anchor="w")

        right = tk.Frame(header, bg=T["bg"])
        right.pack(side="right")
        ttk.Button(right, text="Hide", style="Ghost.TButton", command=self.hide_to_tray).pack(side="right", padx=(8, 0))
        self.status_dot = tk.Canvas(right, width=12, height=12, bg=T["bg"], highlightthickness=0)
        self.status_dot.pack(side="left")
        self._dot_id = self.status_dot.create_oval(1, 1, 11, 11, fill=T["idle"], outline="")
        self.status_value = tk.StringVar(value="Starting...")
        tk.Label(right, textvariable=self.status_value, bg=T["bg"], fg=T["muted"],
                 font=("Segoe UI", 9)).pack(side="left", padx=(6, 0))

        # ---- info card: this PC | VNC partner ----
        info = tk.Frame(outer, bg=T["card"])
        info.pack(fill="x", pady=(10, 6))
        self.ip_value = tk.StringVar(value=self.local_ip)
        self.partner_value = tk.StringVar(value="No active partner")
        self._info_cell(info, 0, "THIS PC", self.ip_value)
        tk.Frame(info, bg=T["line"], width=1).grid(row=0, column=1, sticky="ns", pady=8)
        self._info_cell(info, 2, "VNC PARTNER", self.partner_value)
        info.columnconfigure(0, weight=2)
        info.columnconfigure(2, weight=3)

        # ---- options card ----
        options = tk.Frame(outer, bg=T["card"])
        options.pack(fill="x", pady=(0, 6))
        row = tk.Frame(options, bg=T["card"])
        row.pack(fill="x", padx=10, pady=6)
        self.startup_var = tk.BooleanVar(value=startup_is_enabled())
        ttk.Checkbutton(row, text="Start with Windows", style="Card.TCheckbutton",
                        variable=self.startup_var, command=self._toggle_startup).pack(side="left")
        self.auto_send_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="Auto-send files", style="Card.TCheckbutton",
                        variable=self.auto_send_var, command=self._toggle_auto_send).pack(side="left", padx=(18, 0))
        self.text_sync_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="Sync copied text", style="Card.TCheckbutton",
                        variable=self.text_sync_var, command=self._toggle_text_sync).pack(side="left", padx=(18, 0))

        # ---- action buttons ----
        actions = tk.Frame(outer, bg=T["bg"])
        actions.pack(fill="x", pady=(0, 8))
        ttk.Button(actions, text="Fix firewall", command=self._fix_firewall).pack(side="left")
        ttk.Button(actions, text="Refresh", style="Ghost.TButton", command=self._refresh_now).pack(side="right")

        # ---- transfer progress ----
        prog = tk.Frame(outer, bg=T["bg"])
        prog.pack(fill="x", pady=(0, 8))
        self.progress_text = tk.StringVar(value="Transfer: idle")
        tk.Label(prog, textvariable=self.progress_text, bg=T["bg"], fg=T["muted"],
                 font=("Segoe UI", 8), anchor="w").pack(fill="x")
        self.progress = ttk.Progressbar(prog, maximum=100, style="Slim.Horizontal.TProgressbar")
        self.progress.pack(fill="x", pady=(3, 0))

        # ---- tabs: activity log / discovered computers ----
        self.notebook = ttk.Notebook(outer, style="Dark.TNotebook")
        self.notebook.pack(fill="both", expand=True)

        log_tab = tk.Frame(self.notebook, bg=T["log_bg"])
        self.notebook.add(log_tab, text="  Activity  ")
        self.log_text = tk.Text(
            log_tab, height=6, wrap="word", state="disabled",
            bg=T["log_bg"], fg=T["log_fg"], insertbackground="#ffffff",
            relief="flat", borderwidth=0, highlightthickness=0,
            font=("Consolas", 9), padx=10, pady=8,
        )
        scrollbar = ttk.Scrollbar(log_tab, orient="vertical", command=self.log_text.yview,
                                  style="Dark.Vertical.TScrollbar")
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        for tag, color in (("ts", T["faint"]), ("ok", T["good"]), ("warn", T["warn"]), ("err", T["bad"])):
            self.log_text.tag_configure(tag, foreground=color)

        self.peers_tab = tk.Frame(self.notebook, bg=T["log_bg"])
        self.notebook.add(self.peers_tab, text="  Computers (0)  ")
        columns = ("name", "ip", "status", "last_seen")
        self.peer_tree = ttk.Treeview(self.peers_tab, columns=columns, show="headings", height=4,
                                      style="Dark.Treeview")
        self.peer_tree.heading("name", text="Computer")
        self.peer_tree.heading("ip", text="IP Address")
        self.peer_tree.heading("status", text="Status")
        self.peer_tree.heading("last_seen", text="Last Seen")
        self.peer_tree.column("name", width=170)
        self.peer_tree.column("ip", width=120)
        self.peer_tree.column("status", width=80)
        self.peer_tree.column("last_seen", width=90)
        self.peer_tree.pack(fill="both", expand=True)

        try:  # window / taskbar icon
            from PIL import ImageTk
            self._icon_photo = ImageTk.PhotoImage(self._create_tray_image())
            self.root.iconphoto(True, self._icon_photo)
        except Exception:
            pass

    def _set_partner_active(self, active):
        self.status_dot.itemconfigure(self._dot_id, fill=THEME["good"] if active else THEME["idle"])

    def _log(self, message):
        line = f"[{now_text()}] {message}"
        self.logs.append(line)
        self.ui_queue.put(("log", line))

    def _append_log(self, line):
        stamp, sep, message = line.partition("] ")
        if not sep:
            stamp, message = "", line
        else:
            stamp += "] "
        lower = message.lower()
        if any(w in lower for w in ("failed", "error", "cannot", "could not")):
            tag = "err"
        elif any(w in lower for w in ("rejected", "missing", "denied", "cancelled", "too ")):
            tag = "warn"
        elif any(w in lower for w in ("sent ", "received ", "added", "found", "ready")):
            tag = "ok"
        else:
            tag = ""
        self.log_text.configure(state="normal")
        if stamp:
            self.log_text.insert("end", stamp, "ts")
        self.log_text.insert("end", message + "\n", tag)
        if int(self.log_text.index("end-1c").split(".")[0]) > 500:
            self.log_text.delete("1.0", "100.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _process_ui_queue(self):
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
                if kind == "log":
                    self._append_log(payload)
                elif kind == "peers":
                    self._render_peers(payload)
                elif kind == "status":
                    self.status_value.set(payload)
                elif kind == "partner":
                    self.partner_value.set(payload)
                    self._set_partner_active(payload != "No active partner")
                elif kind == "progress":
                    pct, text = payload
                    self.progress["value"] = pct
                    self.progress_text.set(text)
                elif kind == "firewall_first_run":
                    mark_firewall_prompted()
                    self._fix_firewall(first_run=True)
        except queue.Empty:
            pass
        if not self.stop_event.is_set():
            self.root.after(150, self._process_ui_queue)

    def _discovery_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", DISCOVERY_PORT))
        sock.settimeout(0.5)
        self.discovery_socket = sock
        self.ui_queue.put(("status", "LAN discovery active"))
        self._log("UDP discovery listening.")

        last_announce = 0.0
        while not self.stop_event.is_set():
            now = time.time()
            if now - last_announce >= BROADCAST_INTERVAL:
                packet = {
                    "app": "LANClipboard",
                    "version": APP_VERSION,
                    "id": self.instance_id,
                    "name": self.hostname,
                    "ip": self.local_ip,
                    "transfer_port": TRANSFER_PORT,
                    "time": int(now),
                }
                try:
                    sock.sendto(json.dumps(packet).encode("utf-8"), ("255.255.255.255", DISCOVERY_PORT))
                except OSError as exc:
                    self._log(f"Discovery broadcast error: {exc}")
                last_announce = now

            try:
                data, addr = sock.recvfrom(4096)
                packet = json.loads(data.decode("utf-8", errors="replace"))
                if packet.get("app") != "LANClipboard" or packet.get("id") == self.instance_id:
                    continue
                peer_ip = packet.get("ip") or addr[0]
                peer = {
                    "id": packet.get("id", peer_ip),
                    "name": packet.get("name", "Unknown PC"),
                    "ip": peer_ip,
                    "transfer_port": int(packet.get("transfer_port", TRANSFER_PORT)),
                    "last_seen": time.time(),
                }
                is_new = False
                with self.peers_lock:
                    is_new = peer["id"] not in self.peers
                    self.peers[peer["id"]] = peer
                    snapshot = list(self.peers.values())
                if is_new:
                    self._log(f"Discovered {peer['name']} ({peer_ip}).")
                self.ui_queue.put(("peers", snapshot))
            except socket.timeout:
                pass
            except (OSError, ValueError, json.JSONDecodeError):
                if not self.stop_event.is_set():
                    time.sleep(0.1)

            self._expire_peers()

        try:
            sock.close()
        except OSError:
            pass

    def _expire_peers(self):
        now = time.time()
        removed = []
        with self.peers_lock:
            for peer_id, peer in list(self.peers.items()):
                if now - peer["last_seen"] > PEER_TIMEOUT:
                    removed.append(self.peers.pop(peer_id))
            snapshot = list(self.peers.values())
        for peer in removed:
            self._log(f"{peer['name']} ({peer['ip']}) is offline.")
        if removed:
            self.ui_queue.put(("peers", snapshot))

    def _render_peers(self, peers):
        self.notebook.tab(self.peers_tab, text=f"  Computers ({len(peers)})  ")
        for item in self.peer_tree.get_children():
            self.peer_tree.delete(item)
        for peer in sorted(peers, key=lambda p: p["name"].lower()):
            age = max(0, int(time.time() - peer["last_seen"]))
            self.peer_tree.insert(
                "", "end",
                values=(peer["name"], peer["ip"], "Online", f"{age}s ago")
            )

    def _get_vnc_remote_ips(self):
        """Detect established TCP connections involving common TightVNC ports."""
        found = set()
        try:
            connections = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, OSError) as exc:
            self._log_once("vnc_access", f"Could not inspect TCP connections: {exc}")
            return found

        for conn in connections:
            if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                continue
            try:
                local_port = conn.laddr.port
                remote_port = conn.raddr.port
                if local_port in VNC_PORTS or remote_port in VNC_PORTS:
                    found.add(conn.raddr.ip)
            except (AttributeError, OSError):
                continue
        return found

    def _log_once(self, key, message):
        if not hasattr(self, "_once"):
            self._once = set()
        if key not in self._once:
            self._once.add(key)
            self._log(message)

    def _probe_vnc_peer(self, ip):
        """Find a LAN Clipboard partner straight from a VNC connection (Tailscale, VPN, any route)."""
        now = time.time()
        info = self.probe_cache.setdefault(ip, {"ok_at": 0.0, "checked": 0.0, "name": ip})
        if now - info["checked"] >= (30 if info["ok_at"] else 8):
            info["checked"] = now
            try:
                with socket.create_connection((ip, TRANSFER_PORT), timeout=1.5) as probe:
                    probe.settimeout(1.5)
                    info["name"] = stream_ping(probe) or ip
                info["ok_at"] = now
            except Exception:
                pass
        if now - info["ok_at"] <= 90:  # grace period, e.g. receiver busy with a big transfer
            return {"id": f"vnc-{ip}", "name": info["name"], "ip": ip,
                    "transfer_port": TRANSFER_PORT, "last_seen": info["ok_at"]}
        return None

    def _monitor_loop(self):
        previous_partner = None
        while not self.stop_event.is_set():
            remote_ips = self._get_vnc_remote_ips()
            with self.peers_lock:
                peers_by_ip = {p["ip"]: p for p in self.peers.values()}

            matched = []
            for ip in sorted(remote_ips):
                if ip in peers_by_ip:
                    matched.append(peers_by_ip[ip])
                else:
                    probed = self._probe_vnc_peer(ip)
                    if probed:
                        matched.append(probed)

            partner = matched[0] if matched else None
            self.partners = matched
            self.partner_ips = {p["ip"] for p in matched}
            self.active_partner = partner
            if partner:
                signature = (partner["id"], partner["ip"])
                if signature != previous_partner:
                    self._log(f"Possible TightVNC session with {partner['name']} ({partner['ip']}).")
                    previous_partner = signature
                self.ui_queue.put(("partner", f"{partner['name']} ({partner['ip']})"))
                self.ui_queue.put(("status", "VNC partner detected"))
            else:
                if previous_partner is not None:
                    self._log("No matching active TightVNC partner detected.")
                    previous_partner = None
                self.ui_queue.put(("partner", "No active partner"))
                self.ui_queue.put(("status", "LAN discovery active"))

            time.sleep(2.0)

    # ------------------------------------------------------------------
    # File clipboard transfer (v0.2)
    # ------------------------------------------------------------------
    def _toggle_auto_send(self):
        self.auto_send_enabled = self.auto_send_var.get()
        self._log("Auto-send enabled." if self.auto_send_enabled else "Auto-send disabled (use the button to send).")

    def _set_progress(self, percent, text):
        self.ui_queue.put(("progress", (percent, text)))

    def _make_progress_cb(self, verb):
        state = {"last": 0.0, "start": time.time()}

        def callback(done, total):
            now = time.time()
            if done < total and now - state["last"] < 0.15:
                return
            state["last"] = now
            pct = (done / total * 100) if total else 100
            speed = done / max(now - state["start"], 0.001)
            self._set_progress(pct, f"{verb} {fmt_size(done)} / {fmt_size(total)}  •  {fmt_size(speed)}/s")

        return callback

    def _retire_received(self, delay=CLEANUP_DELAY):
        """The received files are no longer on the clipboard: schedule them for deletion."""
        with self.cleanup_lock:
            if self.current_received:
                self.pending_delete.append([self.current_received, time.time() + delay, 0])
                self.current_received = None

    def _run_pending_cleanup(self):
        now = time.time()
        with self.cleanup_lock:
            keep = []
            for item in self.pending_delete:
                folder, due, tries = item
                if now < due:
                    keep.append(item)
                    continue
                shutil.rmtree(folder, ignore_errors=True)
                if os.path.exists(folder) and tries < 20:  # still in use (paste running?) - retry later
                    item[1], item[2] = now + 30, tries + 1
                    keep.append(item)
            self.pending_delete = keep

    def _place_files_on_clipboard(self, paths, folder=None):
        self._retire_received()  # files from the previous transfer are no longer needed
        # Our own clipboard change must not be re-sent back to the partner.
        self.suppress_until = time.time() + 2.0
        ok = set_clipboard_files(paths)
        self.suppress_until = time.time() + 1.5
        if folder:
            if ok:
                with self.cleanup_lock:
                    self.current_received = folder
            else:
                shutil.rmtree(folder, ignore_errors=True)
        return ok

    def _server_loop(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("", TRANSFER_PORT))
            srv.listen(4)
            srv.settimeout(0.5)
        except OSError as exc:
            self._log(f"Cannot open transfer port {TRANSFER_PORT}: {exc}")
            return
        self.server_socket = srv
        self._log(f"File receiver listening on TCP {TRANSFER_PORT}.")
        while not self.stop_event.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_incoming, args=(conn, addr), daemon=True).start()

    def _handle_incoming(self, conn, addr):
        sender_ip = addr[0]
        name = next((p["name"] for p in self.partners if p["ip"] == sender_ip), sender_ip)
        reject = None
        quiet = False
        if sender_ip not in self.partner_ips:
            reject = "Sender is not an active TightVNC partner of this PC"
        try:
            conn.settimeout(60)
            with self.recv_lock:
                result = stream_receive(
                    conn, INBOX_DIR, reject, self._make_progress_cb("Receiving"), self.text_sync_enabled,
                    self.hostname
                )
            if result["kind"] == "ping":
                quiet = True
            elif result["kind"] == "text":
                if self._place_text_on_clipboard(result["text"]):
                    self._log(f"Received text ({len(result['text'])} chars) from {name}. Ready to paste with Ctrl+V.")
                else:
                    self._log("Received text but could not place it on the clipboard.")
            elif self._place_files_on_clipboard(result["top_paths"], result["folder"]):
                self._log(f"Received {result['count']} item(s), {fmt_size(result['total'])} from {name}. Ready to paste with Ctrl+V.")
            else:
                self._log("Received files but could not place them on the clipboard.")
        except PermissionError:
            self._log(f"Rejected transfer from {sender_ip}: no active TightVNC session with it.")
        except Exception as exc:
            self._log(f"Receive from {name} failed: {exc}")
        finally:
            try:
                conn.close()
            except OSError:
                pass
            if not quiet:
                self._set_progress(0, "Transfer: idle")

    def _clipboard_loop(self):
        if os.name != "nt":
            return
        last_seq = clipboard_sequence()
        while not self.stop_event.wait(CLIPBOARD_POLL):
            self._run_pending_cleanup()
            seq = clipboard_sequence()
            if seq == last_seq:
                continue
            last_seq = seq
            if time.time() < self.suppress_until:
                continue
            time.sleep(0.2)  # let the copying app finish writing its formats
            try:
                paths = get_clipboard_files()
            except Exception as exc:
                self._log_once("clip_err", f"Clipboard read error: {exc}")
                continue
            last_seq = clipboard_sequence()
            if self.current_received and not (paths and all(path_is_inside(p, self.current_received) for p in paths)):
                self._retire_received()  # user copied something else: received files can go
            partners = list(self.partners)
            if not partners:
                continue
            if paths:
                if self.auto_send_enabled:
                    self._queue_send(paths, partners)
                continue
            if not self.text_sync_enabled:
                continue
            try:
                text = get_clipboard_text()
            except Exception as exc:
                self._log_once("clip_text_err", f"Clipboard text read error: {exc}")
                continue
            if not text or text == self.last_text:
                continue
            if len(text) > MAX_TEXT_CHARS:
                self._log(f"Copied text is too long to sync ({len(text)} chars).")
                continue
            self.last_text = text
            self._queue_send_text(text, partners)

    def _queue_send(self, paths, partners):
        def worker():
            with self.send_lock:
                for partner in partners:
                    try:
                        self._send_to_partner(partner, paths)
                    except Exception as exc:
                        self._log(f"Transfer to {partner['name']} failed: {exc}")
                self._set_progress(0, "Transfer: idle")

        threading.Thread(target=worker, daemon=True).start()

    def _send_to_partner(self, partner, paths):
        top, entries, total = collect_entries(paths)
        if not entries:
            self._log("Nothing to send.")
            return
        if total > MAX_TOTAL_BYTES:
            self._log(f"Too large to send ({fmt_size(total)}, limit {fmt_size(MAX_TOTAL_BYTES)}).")
            return
        self._log(f"Sending {len(entries)} item(s), {fmt_size(total)} to {partner['name']} ({partner['ip']})...")
        started = time.time()
        sock = socket.create_connection((partner["ip"], partner["transfer_port"]), timeout=10)
        try:
            sock.settimeout(60)
            stream_send(sock, self.hostname, top, entries, total, self._make_progress_cb("Sending"))
        finally:
            sock.close()
        self._log(f"Sent to {partner['name']} in {time.time() - started:.1f}s. Paste with Ctrl+V there.")

    def _toggle_text_sync(self):
        self.text_sync_enabled = self.text_sync_var.get()
        self._log("Text sync enabled." if self.text_sync_enabled else "Text sync disabled.")

    def _place_text_on_clipboard(self, text):
        self._retire_received()
        self.last_text = text
        self.suppress_until = time.time() + 2.0
        ok = set_clipboard_text(text)
        self.suppress_until = time.time() + 1.5
        return ok

    def _queue_send_text(self, text, partners):
        def worker():
            with self.send_lock:
                for partner in partners:
                    try:
                        sock = socket.create_connection((partner["ip"], partner["transfer_port"]), timeout=10)
                        try:
                            sock.settimeout(30)
                            stream_send_text(sock, self.hostname, text)
                        finally:
                            sock.close()
                        self._log(f"Sent text ({len(text)} chars) to {partner['name']}.")
                    except Exception as exc:
                        self._log(f"Text transfer to {partner['name']} failed: {exc}")

        threading.Thread(target=worker, daemon=True).start()

    def _check_firewall_on_start(self):
        if firewall_rules_exist():
            self._log("Firewall rules for LAN Clipboard found.")
            mark_firewall_prompted()
        elif firewall_prompted():
            self._log("Firewall rules missing. If transfers time out, click 'Fix firewall'.")
        else:
            self.ui_queue.put(("firewall_first_run", None))  # asked only once, on the very first run

    def _fix_firewall(self, first_run=False):
        if os.name != "nt":
            return
        if first_run:
            self._log("First run: Windows will ask permission to open the firewall for LAN Clipboard.")
        elif not messagebox.askyesno(
            "Fix firewall",
            f"This adds Windows Firewall inbound rules for TCP {TRANSFER_PORT} and UDP {DISCOVERY_PORT}.\n"
            "Windows will ask for administrator permission. Continue?",
            parent=self.root,
        ):
            return
        try:
            launched = add_firewall_rules_elevated()
        except Exception as exc:
            self._log(f"Could not start firewall setup: {exc}")
            return
        if not launched:
            self._log("Firewall setup was cancelled or denied.")
            return
        self._log("Adding firewall rules, please wait...")

        def verify():
            for _ in range(10):
                time.sleep(1.5)
                if firewall_rules_exist():
                    self._log("Firewall rules added. Do the same on the other PC if needed.")
                    return
            self._log("Could not confirm the firewall rules. Run the app as administrator and try again.")

        threading.Thread(target=verify, daemon=True).start()

    def _toggle_startup(self):
        enabled = self.startup_var.get()
        try:
            set_startup_enabled(enabled)
            self._log("Start with Windows enabled." if enabled else "Start with Windows disabled.")
        except Exception as exc:
            self.startup_var.set(not enabled)
            messagebox.showerror("Startup setting", str(exc), parent=self.root)

    def _refresh_now(self):
        self.local_ip = local_ip_for()
        self.ip_value.set(self.local_ip)
        self._log("Manual refresh requested.")
        self._log("Peer discovery refreshes automatically every 3 seconds.")

    def _create_tray_image(self):
        image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((5, 5, 59, 59), radius=12, fill=(14, 165, 233, 255))
        draw.rectangle((15, 17, 49, 40), outline="white", width=3)
        draw.line((25, 47, 39, 47), fill="white", width=3)
        draw.line((32, 40, 32, 47), fill="white", width=3)
        return image

    def _start_tray(self):
        if self.tray_icon is not None:
            return
        menu = pystray.Menu(
            pystray.MenuItem("Open LAN Clipboard", self._tray_show, default=True),
            pystray.MenuItem("Exit", self._tray_exit),
        )
        self.tray_icon = pystray.Icon(APP_NAME, self._create_tray_image(), APP_NAME, menu)
        self.tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
        self.tray_thread.start()

    def _tray_show(self, icon=None, item=None):
        self.root.after(0, self.show_window)

    def _tray_exit(self, icon=None, item=None):
        self.root.after(0, self.shutdown)

    def show_window(self):
        self.root.deiconify()
        self.root.lift()
        try:
            self.root.focus_force()
        except tk.TclError:
            pass

    def hide_to_tray(self):
        if self.tray_icon is None:
            self.root.iconify()
        else:
            self.root.withdraw()

    def shutdown(self):
        if self.stop_event.is_set():
            return
        self._log("Shutting down...")
        self.stop_event.set()
        wipe_inbox()
        try:
            if self.discovery_socket:
                self.discovery_socket.close()
        except OSError:
            pass
        try:
            if self.server_socket:
                self.server_socket.close()
        except OSError:
            pass
        try:
            if self.tray_icon:
                self.tray_icon.stop()
        except Exception:
            pass
        self.root.after(100, self.root.destroy)

    def run(self):
        self.root.mainloop()


def main():
    if os.name != "nt":
        print("LAN Clipboard is designed for Windows.")
        return
    start_minimized = "--minimized" in sys.argv
    app = LANClipboardApp(start_minimized=start_minimized)
    app.run()


if __name__ == "__main__":
    main()
