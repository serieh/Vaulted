import argparse, base64, json, logging, os, sys, time, socket, secrets, getpass, subprocess, shutil, io
from typing import Optional, Dict, Any, Callable
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------- crypto libs ----------------------------------
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except Exception:
    print("Missing dependency 'cryptography'. Install: pip install cryptography")
    raise

try:
    from argon2.low_level import hash_secret_raw, Type
    HAVE_ARGON2 = True
except Exception:
    HAVE_ARGON2 = False

try:
    import keyring
    HAVE_KEYRING = True
except Exception:
    HAVE_KEYRING = False

# ---------------------------------- Google Drive libs ----------------------------------
try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
    from googleapiclient.http import MediaIoBaseUpload
except Exception:
    print("Missing Google API deps. Install: pip install google-auth google-auth-oauthlib google-api-python-client")
    raise

# ---------------------------------- plyer (notification) ----------------------------------
try:
    from plyer import notification
    HAVE_PLYER = True
except Exception:
    HAVE_PLYER = False

# ---------------------------------- configuration ----------------------------------
APP_NAME = "Vaulted"
VERSION = f"{APP_NAME} v2.5"
DRIVE_FOLDER_NAME_DEFAULT = "Vaulted_Backups"
KEYRING_SERVICE = "Vaulted-backup-passphrase"
HOME_PATH = Path.home()

DEFAULT_CONFIG_DIR = HOME_PATH / "Vaulted"
DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR.joinpath("config.json")
CLIENT_SECRETS_FILE = DEFAULT_CONFIG_DIR.joinpath("client_secret.json")
TOKEN_FILE = DEFAULT_CONFIG_DIR.joinpath("token.json")

SCOPES = ["https://www.googleapis.com/auth/drive"]
RETENTION_DEFAULT = 5

# Retrying
MAX_RETRYS = 4
BACKOFF = 0.1

# ---------------------------------- logging ----------------------------------
logger = logging.getLogger(APP_NAME)
# Set the logger level to DEBUG to capture all messages
logger.setLevel(logging.DEBUG)

# Create a formatter for both handlers
formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")

# Handler for the terminal (console)
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)

# Handler for the log file
log_file_path = DEFAULT_CONFIG_DIR.joinpath("Vaulted.log")
file_handler = logging.FileHandler(log_file_path)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# ---------------------------------- helpers ----------------------------------

def write_json(path: Path, obj: Any, mode: int = 0o600) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf8") as f:
        json.dump(obj, f, indent=2)
    os.chmod(tmp, mode)
    tmp.replace(path)

def read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf8") as f:
        return json.load(f)

def is_connected(host: str = "8.8.8.8", port: int = 53, timeout: float = 3.0) -> bool:
    try:
        socket.setdefaulttimeout(timeout)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
        return True
    except OSError:
        return False

def get_username() -> str:
    return getpass.getuser()

def prompt_passphrase(confirm: bool = True) -> str:
    while True:
        p = getpass.getpass("Enter passphrase (min 8 characters): ")
        if not p or len(p) < 8:
            print("Passphrase too short or empty. Please try again.")
            continue
        if not confirm:
            return p
        q = getpass.getpass("Confirm passphrase: ")
        if p != q:
            print("Passphrases do not match. Please try again.")
            continue
        return p


def make_notifier(disabled: bool = False) -> Callable[[str, str], None]:
    if disabled:
        return lambda title, msg: logger.info("%s: %s", title, msg)

    def notify(title: str, message: str) -> None:
        try:
            if HAVE_PLYER:
                notification.notify(title=title, message=message)
                return
        except Exception as e:
            logger.debug("plyer notify failed: %s", e)

        try:
            if sys.platform == "darwin":
                subprocess.run(["osascript", "-e", f'display notification "{message}" with title "{title}"'], check=False)
                return
            if sys.platform.startswith("linux"):
                subprocess.run(["notify-send", title, message], check=False)
                return
            if sys.platform == "win32":
                logger.info("%s: %s", title, message)
                return
        except Exception as e:
            logger.debug("fallback notify failed: %s", e)
        # final fallback
        logger.info("%s: %s", title, message)

    return notify

# ---------------------------------- crypto KDF & AES-GCM ----------------------------------
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32

def derive_key_from_passphrase(passphrase: str, salt: bytes, *, key_len: int = KEY_LEN, params: Optional[Dict[str, int]] = None) -> bytes:
    pw = passphrase.encode("utf-8")
    if HAVE_ARGON2:
        if not params:
            params = {"time_cost": 2, "memory_cost": 2 ** 16, "parallelism": 1}
        key = hash_secret_raw(secret=pw, salt=salt,
                              time_cost=params.get("time_cost", 2),
                              memory_cost=params.get("memory_cost", 2 ** 16),
                              parallelism=params.get("parallelism", 1),
                              hash_len=key_len,
                              type=Type.ID)
        return key
    else:
        iterations = params.get("iterations", 200_000) if params else 200_000
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_len, salt=salt, iterations=iterations, backend=default_backend())
        return kdf.derive(pw)

def encrypt_bytes(plaintext: bytes, passphrase: str) -> bytes:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = derive_key_from_passphrase(passphrase, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    wrapper = {
        "version": 1,
        "kdf": "argon2id" if HAVE_ARGON2 else "pbkdf2",
        "kdf_salt": base64.b64encode(salt).decode("ascii"),
        "kdf_params": {"time_cost": 2, "memory_cost": 2 ** 16, "parallelism": 1} if HAVE_ARGON2 else {"iterations": 200000},
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    return json.dumps(wrapper).encode("utf-8")

def decrypt_bytes(wrapper_bytes: bytes, passphrase: str) -> bytes:
    wrapper = json.loads(wrapper_bytes)
    salt = base64.b64decode(wrapper["kdf_salt"])
    nonce = base64.b64decode(wrapper["nonce"])
    ciphertext = base64.b64decode(wrapper["ciphertext"])
    params = wrapper.get("kdf_params", None)
    key = derive_key_from_passphrase(passphrase, salt, params=params)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# ---------------------------------- google drive helpers (with retries) ----------------------------------

def retry_on_exception():
    def decorator(fn):
        def wrapper(*args, **kwargs):
            attempt = 0
            while True:
                try:
                    return fn(*args, **kwargs)
                except HttpError as e:
                    attempt += 1
                    if attempt > MAX_RETRYS:
                        raise
                    sleep = BACKOFF * (2 ** (attempt - 1))
                    logger.warning("HttpError during %s (attempt %d/%d): %s. Sleeping %.1fs and retrying", fn.__name__, attempt, MAX_RETRYS, e, sleep)
                    time.sleep(sleep)
                except OSError:
                    attempt += 1
                    if attempt > MAX_RETRYS:
                        raise
                    time.sleep(BACKOFF * (2 ** (attempt - 1)))
        return wrapper
    return decorator

def check_credentials(client_secrets_path: Path, token_path: Path) -> Credentials:
    creds = None
    if token_path.exists():
        try:
            creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
        except Exception:
            logger.info("Failed to parse token; reauthorizing.")
            creds = None

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception:
                creds = None
        if not creds:
            if not client_secrets_path.exists():
                raise FileNotFoundError(f"Client secrets not found at {client_secrets_path}")
            flow = InstalledAppFlow.from_client_secrets_file(str(client_secrets_path), SCOPES)
            creds = flow.run_local_server(port=0)

        token_path.parent.mkdir(parents=True, exist_ok=True)
        write_json(token_path, json.loads(creds.to_json()))
    return creds

@retry_on_exception()
def drive_folder(service, folder_name: str) -> str:
    query = f"name='{folder_name.replace("'", "\\'")}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
    resp = service.files().list(q=query, spaces='drive', fields='files(id)').execute()
    files = resp.get("files", [])
    if files:
        return files[0]["id"]
    meta = {"name": folder_name, "mimeType": "application/vnd.google-apps.folder"}
    folder = service.files().create(body=meta, fields="id").execute()
    return folder["id"]

@retry_on_exception()
def upload_backup(service, enc_stream, folder_id: str, filename: str) -> Dict[str, Any]:
    media = MediaIoBaseUpload(enc_stream, mimetype='application/octet-stream', resumable=True)
    file_metadata = {"name": filename, "parents": [folder_id]}
    f = service.files().create(body=file_metadata, media_body=media, fields="id, createdTime").execute()
    return f

@retry_on_exception()
def list_backups(service, folder_id: str):
    query = f"'{folder_id}' in parents and name contains 'v_' and trashed = false"
    files = []
    page_token = None
    while True:
        res = service.files().list(q=query, spaces='drive', fields='nextPageToken,files(id,name,createdTime)', pageToken=page_token).execute()
        files.extend(res.get("files", []))
        page_token = res.get("nextPageToken")
        if not page_token:
            break
    files.sort(key=lambda f: f['createdTime'])
    return files

@retry_on_exception()
def prune_old_backups(service, folder_id: str, keep: int):
    files = list_backups(service, folder_id)
    while len(files) > keep:
        to_delete = files.pop(0)
        try:
            service.files().delete(fileId=to_delete['id']).execute()
            logger.info("Deleted old backup %s", to_delete['name'])
        except Exception as e:
            logger.warning("Failed to delete %s: %s", to_delete.get('name'), e)

# ---------------------------------- bookmark helpers ----------------------------------
def default_brave_bookmarks_file() -> Path:
    home = Path.home()
    if sys.platform == "win32":
        return home / "AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Bookmarks"
    elif sys.platform == "darwin":
        return home / "Library/Application Support/BraveSoftware/Brave-Browser/Default/Bookmarks"
    else:
        return home / ".config/BraveSoftware/Brave-Browser/Default/Bookmarks"

def default_output_file(infile:Path) -> Path:
    return  (Path.home() / "Desktop" / (infile.stem + ".html"))

# ---------------------------------- flows ----------------------------------

def setup(config_path: Path, cfg: Dict[str, Any], notifier: Callable[[str, str],None]):
    print("=== Vaulted setup ===")
    p = prompt_passphrase(confirm=True)
    store_choice = False
    if HAVE_KEYRING:
        ans = input("Store passphrase in OS keyring for automatic backups? [Y/n]: ")
        store_choice = ans.strip().lower() not in ("n", "no")
    else:
        print("keyring not available; passphrase can't be stored in OS keyring.")

    if store_choice:
        keyring.set_password(KEYRING_SERVICE, get_username(), p)
        cfg['store_passphrase'] = True
    else:
        cfg['store_passphrase'] = False

    file_path = None
    while True:
        file = input("Enter a valid path of the file that will be backed up [Default: Brave Bookmarks file]:").strip()
        if not file:
            file_path = default_brave_bookmarks_file()
            print("Using defaults...\n")
            break
        elif os.path.isfile(file):
            file_path = file
            break
        else:
            print(f"'{file}' is not a valid file path, try again\n")

    cfg.setdefault('drive_folder', DRIVE_FOLDER_NAME_DEFAULT)
    cfg.setdefault('retention', RETENTION_DEFAULT)
    cfg.setdefault('client_secrets', str(CLIENT_SECRETS_FILE))
    cfg.setdefault('token_file', str(TOKEN_FILE))
    cfg.setdefault('file_path' , str(file_path))

    write_json(config_path, cfg)
    print("Setup complete.")
    run_now = input("Run backup now? [Y/n]: ")
    if run_now.strip().lower() not in ("n", "no"):
        run(cfg, notifier, passphrase=p)

def run(infile: Optional[Path], outpath: Optional[Path], cfg: Dict[str, Any], notifier: Callable[[str, str],None], passphrase: Optional[str] = None, dry_run: bool = False):
    # Check Internet Connection
    if not is_connected() and not outpath:
        msg = "No internet connection — backup skipped"
        logger.error(msg)
        notifier("Bookmarks Backup", msg)
        raise RuntimeError(msg)

    file_path = None
    if infile:
        file_path = infile
    else:
        file_path = Path(cfg.get('file_path') or default_brave_bookmarks_file())
    if not file_path.exists():
        raise FileNotFoundError(f"File not found at {file_path}")
    data = file_path.read_bytes()

    if not passphrase:
        if cfg.get('store_passphrase') and HAVE_KEYRING:
            try:
                passphrase = keyring.get_password(KEYRING_SERVICE, get_username())
            except Exception:
                pass
        if not passphrase:
            passphrase = getpass.getpass("Enter passphrase to encrypt backups: ")

    enc = encrypt_bytes(data, passphrase)
    filename = f"v_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.enc"

    try:
        if outpath and outpath.is_dir():
            dest = outpath / filename
            dest.write_bytes(enc)
            notifier("Vaulted", f"Success: saved encrypted backup to {dest}")
            logger.info("Saved encrypted backup to %s", dest)
            return

        creds = check_credentials(Path(cfg.get('client_secrets', CLIENT_SECRETS_FILE)), Path(cfg.get('token_file', TOKEN_FILE)))
        service = build('drive', 'v3', credentials=creds)
        folder_id = drive_folder(service, cfg.get('drive_folder', DRIVE_FOLDER_NAME_DEFAULT))
        uploaded = upload_backup(service, io.BytesIO(enc), folder_id, filename)
        prune_old_backups(service, folder_id, int(cfg.get('retention', RETENTION_DEFAULT)))
        notifier("Vaulted", f"Success: uploaded {filename}")
        logger.info("Uploaded %s (id=%s)", filename, uploaded.get('id'))
    finally:
        try:
            tmp_path.unlink()
        except Exception:
            pass

def decrypt(infile: Path, outfile: Optional[Path], cfg: Dict[str, Any]):
    if not infile.exists():
        raise FileNotFoundError("Input file missing")

    passphrase = None
    passphrase = os.environ.get("VAULTED_PASSPHRASE")
    if not passphrase:
        passphrase = getpass.getpass("Enter passphrase to decrypt: ")

    wrapped = infile.read_bytes()
    try:
        plaintext = decrypt_bytes(wrapped, passphrase)
    except Exception:
        logger.exception("Decryption failed")
        raise ValueError("Decryption failed: invalid passphrase or corrupt file")

    outpath = outfile or default_output_file(infile)
    outpath.parent.mkdir(parents=True, exist_ok=True)

    if outpath.exists():
        base = outpath.with_suffix("")
        ext = outpath.suffix or ""
        counter = 1
        backup_path = outpath.with_name(f"{base.name}_({counter}){ext}")
        while backup_path.exists():
            counter += 1
            backup_path = outpath.with_name(f"{base.name}_({counter}){ext}")
        outpath.replace(backup_path)
        logger.info("Existing output backed up to %s", backup_path)

    outpath.write_bytes(plaintext)
    logger.info("Wrote decrypted file to %s", outpath)
    print(f"Decrypted -> {outpath}")

# ---------------------------------- config loading ----------------------------------
def load_config(path: Path) -> Dict[str, Any]:
    cfg = read_json(path)
    cfg.setdefault('drive_folder', DRIVE_FOLDER_NAME_DEFAULT)
    cfg.setdefault('retention', RETENTION_DEFAULT)
    cfg.setdefault('client_secrets', str(CLIENT_SECRETS_FILE))
    cfg.setdefault('token_file', str(TOKEN_FILE))
    cfg.setdefault('store_passphrase', False)
    return cfg

# ---------------------------------- CLI ----------------------------------
def help(args):
    parser.print_help()
    sys.exit(0)


def main(argv=None):
    global parser
    parser = argparse.ArgumentParser(
        prog="Vaulted",
        description="Vaulted — Encrypted Bookmarks or files backups to Google Drive.",
    )

    parser.add_argument("--config", "-c", default=str(DEFAULT_CONFIG_FILE),
                        help="Path to config JSON (created by 'setup')")
    parser.add_argument("--no-notify", "-n", action="store_true",
                        help="Disable desktop notifications (log only).")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose logging (DEBUG).")
    parser.add_argument("--version", action="version", version=VERSION,
                        help="Show program version and exit.")

    # subcommands
    sub = parser.add_subparsers(dest="cmd")
    parser.set_defaults(func=help)

    sp_setup = sub.add_parser("setup", help="Initial setup",
                              description="Interactive setup: choose drive folder, retention and optionally store passphrase in the OS keyring.")
    sp_setup.set_defaults(func=lambda args: setup(Path(args.config), load_config(Path(args.config)), make_notifier(disabled=args.no_notify)))

    sp_run = sub.add_parser("run", help="Run a backup now",
                            description="Create an encrypted snapshot of a file and upload it to Google Drive.")
    sp_run.add_argument("-i", "--in", dest="infile", help="Input file path that will be backed-up (optional).")
    sp_run.add_argument("-o", "--out", dest="outpath", help="Save encrypted file to destination path <save to device, not drive> (optional).")
    sp_run.set_defaults(
        func=lambda args: run(
            Path(args.infile) if args.infile else None,
            Path(args.outpath) if args.outpath else None,
            load_config(Path(args.config)),
            make_notifier(disabled=args.no_notify),
            passphrase=None
        )
    )
    sp_decrypt = sub.add_parser("decrypt", help="Decrypt an encrypted backup file",
                                description="Decrypt a bm_*.enc file created by this tool. Writes plaintext to -o or Desktop by default.")
    sp_decrypt.add_argument("-i", "--in", dest="infile", required=True, help="Encrypted input file (bm_*.enc)")
    sp_decrypt.add_argument("-o", "--out", dest="outfile", help="Destination path for decrypted file (optional).")
    sp_decrypt.set_defaults(func=lambda args: decrypt(Path(args.infile), Path(args.outfile) if args.outfile else None, load_config(Path(args.config))))

    args = parser.parse_args(argv)
    if getattr(args, "verbose", False):
        logger.setLevel(logging.DEBUG)

    args.func(args)


if __name__ == "__main__":
    main()
