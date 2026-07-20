import os
import re
import sys
import json
import time
import uuid
import shutil
import sqlite3
import subprocess
import threading
import queue
import hmac
import hashlib
import secrets
import datetime
import urllib.request
import urllib.parse
from pathlib import Path

from flask import Flask, request, jsonify, send_file, Response, session

app = Flask(__name__)

# --- Config loading ---
# Load a local ".env" (KEY=VALUE) sitting next to this file, then read every
# setting from the environment. No credentials are hard-coded in the source;
# see .env.example for the full list of settings.
SRC_DIR = Path(__file__).resolve().parent
BIN_DIR = SRC_DIR / 'bin'


def _load_dotenv():
    p = SRC_DIR / '.env'
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, _, v = line.partition('=')
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()


def env(key, default=None):
    v = os.environ.get(key)
    return v if v not in (None, '') else default


BASE_DIR = Path(env('DATA_DIR', '/var/tmp/macOSAppstoreDecrypter'))
IPA_DIR = BASE_DIR / 'ipas'
DB_PATH = BASE_DIR / 'cache.db'

# Persistent Flask secret (so login sessions survive restarts).
_SECRET_FILE = BASE_DIR / '.flask_secret'
BASE_DIR.mkdir(parents=True, exist_ok=True)
if not _SECRET_FILE.exists():
    _SECRET_FILE.write_text(secrets.token_hex(32))
app.secret_key = _SECRET_FILE.read_text().strip()
app.permanent_session_lifetime = datetime.timedelta(days=30)
DAILY_FREE_LIMIT = int(env('DAILY_FREE_LIMIT', '5'))   # free apps a normal approved user may request per day (GMT+7)
IPATOOL = env('IPATOOL_BIN') or str(BIN_DIR / 'ipatool')
UNFAIR = env('UNFAIR_BIN') or str(BIN_DIR / 'unfair-core')
KEYCHAIN_PATH = env('KEYCHAIN_PATH') or os.path.expanduser('~/Library/Keychains/login.keychain-db')
DISK_RESERVE_GB = int(env('DISK_RESERVE_GB', '20'))   # evict old decrypt cache to keep at least this many GB free
CACHE_TTL_DAYS = int(env('CACHE_TTL_DAYS', '7'))
STORE_COUNTRY = env('STORE_COUNTRY', 'us')

IPA_DIR.mkdir(parents=True, exist_ok=True)

BLACKLIST = {
    'AsheKube.app.a-Shell': 'This app is too large and causes extraction errors. Not supported.',
    'AsheKube.app.a-Shell-mini': 'This app causes extraction errors. Not supported.',
    'AsheKube.Carnets': 'This app causes extraction errors. Not supported.',
    'AsheKube.CarnetsSci': 'This app causes extraction errors. Not supported.',
    # 'com.spotify.client': 'Paid app, not supported.',
}

BLACKLIST_PREFIXES = {
    # (Google apps were blocked here claiming "DRM"; the real cause was OOM on
    #  this 8 GB box, not DRM — removed. Very large apps may still fail on RAM.)
}

import resource
try:
    resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))
except Exception:
    pass

# Response cache for expensive endpoints
_cache = {}
_cache_lock = threading.Lock()


def cached_response(key, ttl=300):
    with _cache_lock:
        if key in _cache:
            data, ts = _cache[key]
            if time.time() - ts < ttl:
                return data
    return None


def set_cache(key, data):
    with _cache_lock:
        _cache[key] = (data, time.time())


# Preloaded index HTML
_index_html = None


def get_index_html():
    global _index_html
    if _index_html is None:
        html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'index.html')
        with open(html_path) as f:
            _index_html = f.read()
    return _index_html

job_lock = threading.Lock()
jobs = {}
decrypt_queue = queue.Queue()
download_semaphore = threading.Semaphore(5)
user_download_semaphore = threading.Semaphore(5)

# --- Decrypt concurrency: DYNAMIC, scales with free RAM ---
# We spawn DECRYPT_HARD_CAP worker threads, but the number actually decrypting at
# once is decided live from available RAM:
#     target = available_GB / DECRYPT_GB_PER_SLOT   (clamped to [MIN, HARD_CAP])
# So on a box with lots of free RAM it can run many in parallel (up to the cap),
# and on a tight box it backs off — but ALWAYS ≥1 so the queue never stalls.
# Each decrypt runs in its own TMPDIR (see run_decrypt) so payloads never overlap.
# Tuning: lower DECRYPT_GB_PER_SLOT = more parallel workers; raise it = safer.
DECRYPT_HARD_CAP = 10            # absolute max concurrent decrypts (and worker threads)
DECRYPT_MIN_CONCURRENT = 1       # always allow at least this many
DECRYPT_GB_PER_SLOT = 1.2        # estimated RAM budget per concurrent decrypt
MAX_DECRYPT_WORKERS = DECRYPT_HARD_CAP
_decrypt_cv = threading.Condition()
_decrypt_running = 0
google_lock = threading.Lock()   # serialize heavy Google-app decrypts (one at a time)


def _available_ram_gb():
    """Best-effort available memory (free + inactive + speculative + purgeable).
    Returns 0.0 on error so we stay conservative and don't over-commit RAM."""
    try:
        out = subprocess.run(['vm_stat'], capture_output=True, text=True, timeout=5).stdout
        psize = 16384
        m = re.search(r'page size of (\d+) bytes', out)
        if m:
            psize = int(m.group(1))

        def pg(name):
            mm = re.search(name + r':\s+(\d+)\.', out)
            return int(mm.group(1)) if mm else 0

        # Only count memory that is ACTUALLY free right now. We deliberately
        # exclude "inactive" (file cache): mremap_encrypted needs real free
        # physical/wired pages, and counting reclaimable cache led us to run too
        # many concurrent decrypts on this 8 GB box → mremap "Cannot allocate
        # memory". On a big-RAM machine free is large, so concurrency still scales.
        pages = pg('Pages free') + pg('Pages purgeable') + pg('Pages speculative')
        return pages * psize / (1024 ** 3)
    except Exception:
        return 0.0


def _mem_available_gb():
    """macOS-style AVAILABLE memory for the /logs display: free + inactive +
    speculative + purgeable. Unlike _available_ram_gb() (used for the decrypt
    gate) this counts reclaimable 'inactive' cache, so it matches what Activity
    Monitor shows and moves when apps free RAM."""
    try:
        out = subprocess.run(['vm_stat'], capture_output=True, text=True, timeout=5).stdout
        psize = 16384
        m = re.search(r'page size of (\d+) bytes', out)
        if m:
            psize = int(m.group(1))

        def pg(name):
            mm = re.search(name + r':\s+(\d+)\.', out)
            return int(mm.group(1)) if mm else 0

        pages = (pg('Pages free') + pg('Pages inactive')
                 + pg('Pages speculative') + pg('Pages purgeable'))
        return pages * psize / (1024 ** 3)
    except Exception:
        return 0.0


def _target_concurrency():
    """How many decrypts may run right now, derived from available RAM."""
    n = int(_available_ram_gb() // DECRYPT_GB_PER_SLOT)
    return max(DECRYPT_MIN_CONCURRENT, min(DECRYPT_HARD_CAP, n))


def acquire_decrypt_slot(log):
    """Block until RAM allows another decrypt. First one always runs."""
    global _decrypt_running
    with _decrypt_cv:
        while True:
            target = _target_concurrency()
            if _decrypt_running == 0 or _decrypt_running < target:
                _decrypt_running += 1
                return
            log(f'Holding decrypt — RAM allows {target} at once, {_decrypt_running} already running...')
            _decrypt_cv.wait(timeout=8)


def release_decrypt_slot():
    global _decrypt_running
    with _decrypt_cv:
        if _decrypt_running > 0:
            _decrypt_running -= 1
        _decrypt_cv.notify_all()


# --- Intake pause: when this flag file exists, new decrypt requests are refused
# (existing queue keeps running). Toggle via /api/v1/pause and /api/v1/resume
# (LAN/localhost only). The flag is a file so it survives restarts. ---
PAUSE_FLAG = BASE_DIR / 'PAUSED'


def intake_paused():
    try:
        return PAUSE_FLAG.exists()
    except Exception:
        return False


# --- Open mode ---
# When the OPEN_MODE flag file exists, the login/approval/quota gate on NEW
# decrypts is lifted: anyone can decrypt unlimited apps without an account.
# Toggled from the admin dashboard; stored as a file so it survives restarts.
OPEN_MODE_FLAG = BASE_DIR / 'OPEN_MODE'


def open_mode_on():
    try:
        return OPEN_MODE_FLAG.exists()
    except Exception:
        return False


# Rate limiter per IP
rate_lock = threading.Lock()
rate_buckets = {}  # ip -> [timestamps]
RATE_LIMIT = 30  # requests per window
RATE_WINDOW = 60  # seconds
# Localhost + private LAN ranges always bypass the per-IP rate limit. Add your
# own trusted public IPs via RATE_WHITELIST (comma-separated) in .env.
RATE_WHITELIST_EXACT = {'127.0.0.1', '::1'} | {
    ip.strip() for ip in (env('RATE_WHITELIST', '') or '').split(',') if ip.strip()}
RATE_WHITELIST_PREFIX = ('192.168.', '10.', '172.16.', '127.', 'fe80:')


def check_rate_limit(ip):
    # Per-IP rate limiting disabled — always allow.
    return True
    if ip in RATE_WHITELIST_EXACT or ip.startswith(RATE_WHITELIST_PREFIX):
        return True
    now = time.time()
    with rate_lock:
        if ip not in rate_buckets:
            rate_buckets[ip] = []
        bucket = rate_buckets[ip]
        rate_buckets[ip] = [t for t in bucket if now - t < RATE_WINDOW]
        if len(rate_buckets[ip]) >= RATE_LIMIT:
            return False
        rate_buckets[ip].append(now)
        return True


def cleanup_rate_buckets():
    while True:
        time.sleep(300)
        now = time.time()
        with rate_lock:
            dead = [ip for ip, ts in rate_buckets.items() if not ts or now - ts[-1] > RATE_WINDOW * 2]
            for ip in dead:
                del rate_buckets[ip]

_thread_local = threading.local()


def get_db():
    conn = getattr(_thread_local, 'db_conn', None)
    if conn is None:
        conn = sqlite3.connect(str(DB_PATH), timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        _thread_local.db_conn = conn
    return conn


def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS cached_ipas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bundle_id TEXT NOT NULL,
            app_name TEXT NOT NULL,
            version TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER NOT NULL DEFAULT 0,
            decrypted_at INTEGER NOT NULL,
            last_requested INTEGER NOT NULL,
            region TEXT NOT NULL DEFAULT 'vn',
            UNIQUE(bundle_id, version, region)
        );
        CREATE INDEX IF NOT EXISTS idx_bundle ON cached_ipas(bundle_id);
        CREATE INDEX IF NOT EXISTS idx_last_req ON cached_ipas(last_requested);

        CREATE TABLE IF NOT EXISTS whitelisted_apps (
            bundle_id TEXT PRIMARY KEY,
            app_name TEXT NOT NULL
        );

        INSERT OR IGNORE INTO whitelisted_apps (bundle_id, app_name) VALUES
            ('com.mojang.minecraftpe', 'Minecraft'),
            ('com.innersloth.amongus', 'Among Us');

        CREATE TABLE IF NOT EXISTS purchased_apps (
            bundle_id TEXT PRIMARY KEY,
            purchased_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            pass_hash TEXT NOT NULL,
            approved INTEGER NOT NULL DEFAULT 0,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            req_count INTEGER NOT NULL DEFAULT 0,
            req_day TEXT DEFAULT ''
        );
    ''')

    # Migration: rebuild a pre-existing cached_ipas (older DBs) to add the
    # region column and the region-aware UNIQUE(bundle_id, version, region).
    # A plain ALTER ADD COLUMN can't change the old UNIQUE(bundle_id, version),
    # which would let a same-version app in another region clobber the VN row.
    # Existing rows were all downloaded with the VN account, so default 'vn'.
    cols = [r[1] for r in conn.execute("PRAGMA table_info(cached_ipas)").fetchall()]
    if 'region' not in cols:
        conn.executescript('''
            ALTER TABLE cached_ipas RENAME TO cached_ipas_old;
            CREATE TABLE cached_ipas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bundle_id TEXT NOT NULL,
                app_name TEXT NOT NULL,
                version TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL DEFAULT 0,
                decrypted_at INTEGER NOT NULL,
                last_requested INTEGER NOT NULL,
                region TEXT NOT NULL DEFAULT 'vn',
                UNIQUE(bundle_id, version, region)
            );
            INSERT INTO cached_ipas
                (id, bundle_id, app_name, version, file_path, file_size, decrypted_at, last_requested, region)
                SELECT id, bundle_id, app_name, version, file_path, file_size, decrypted_at, last_requested, 'vn'
                FROM cached_ipas_old;
            DROP TABLE cached_ipas_old;
            CREATE INDEX IF NOT EXISTS idx_bundle ON cached_ipas(bundle_id);
            CREATE INDEX IF NOT EXISTS idx_last_req ON cached_ipas(last_requested);
        ''')

    conn.commit()
    ensure_admin()
    pass  # thread-local conn, no close


# ==================== USER ACCOUNTS / AUTH ====================
def _hash_pw(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 120000).hex()
    return f'{salt}${h}'


def _verify_pw(password, stored):
    try:
        salt = stored.split('$', 1)[0]
    except Exception:
        return False
    return hmac.compare_digest(_hash_pw(password, salt), stored)


def gmt7_today():
    return (datetime.datetime.utcnow() + datetime.timedelta(hours=7)).strftime('%Y-%m-%d')


def current_user():
    uid = session.get('uid')
    if not uid:
        return None
    try:
        return get_db().execute('SELECT * FROM users WHERE id = ?', (uid,)).fetchone()
    except Exception:
        return None


def is_admin_user():
    u = current_user()
    return bool(u and u['is_admin'])


def user_public(u):
    if not u:
        return None
    used = u['req_count'] if u['req_day'] == gmt7_today() else 0
    admin = bool(u['is_admin'])
    return {
        'email': u['email'], 'name': u['name'],
        'approved': bool(u['approved']), 'is_admin': admin,
        'used_today': used,
        'limit': (None if admin else DAILY_FREE_LIMIT),
        'remaining': (None if admin else max(0, DAILY_FREE_LIMIT - used)),
    }


def ensure_admin():
    """Create a default admin on first run and write its password to a local-only
    file so the operator can read it (then change it)."""
    conn = get_db()
    if conn.execute('SELECT COUNT(*) c FROM users WHERE is_admin = 1').fetchone()['c'] == 0:
        admin_email = env('ADMIN_EMAIL', 'admin@localhost')
        pw = env('ADMIN_PASSWORD') or ('Admin-' + secrets.token_hex(4))
        conn.execute(
            'INSERT OR IGNORE INTO users (email, name, pass_hash, approved, is_admin, created_at) '
            'VALUES (?,?,?,1,1,?)',
            (admin_email, 'Admin', _hash_pw(pw), int(time.time())))
        conn.commit()
        try:
            (BASE_DIR / 'ADMIN_PASSWORD.txt').write_text(f'{admin_email}\n{pw}\n')
        except Exception:
            pass
        print(f'[admin] default admin created: {admin_email} / {pw}', flush=True)


SUDO_PASS = env('MAC_PASSWORD', '')   # macOS login password: used for `sudo` (launchctl asuser, purge) and to unlock the keychain. Set in .env.

# --- App Store accounts (one Apple ID per storefront/region) ---
# ipatool can only be logged into one Apple ID per config dir ($HOME/.ipatool),
# so each region gets its own Apple ID and an isolated HOME; ipatool_cmd(...,
# region=r) runs ipatool with that HOME. Configure regions WITHOUT editing this
# file, in one of two ways (see .env.example):
#   * Single region : set APPLE_ID_EMAIL / APPLE_ID_PASSWORD / STORE_COUNTRY.
#   * Multiple regions: set REGIONS_JSON, or drop a regions.json next to app.py.
# Each region entry -> {email, pass, home, country (2-letter store), label}.
#   country -> iTunes lookup/search storefront; home -> HOME passed to ipatool.


def _load_regions():
    raw = env('REGIONS_JSON')
    data = {}
    if raw:
        try:
            data = json.loads(raw)
        except Exception:
            data = {}
    if not data:
        f = SRC_DIR / 'regions.json'
        if f.exists():
            try:
                data = json.loads(f.read_text())
            except Exception:
                data = {}
    if not data:
        # Fall back to a single region built from the simple APPLE_ID_* vars.
        data = {STORE_COUNTRY: {
            'email': env('APPLE_ID_EMAIL', ''),
            'pass': env('APPLE_ID_PASSWORD', ''),
            'home': '~', 'country': STORE_COUNTRY}}
    for key, v in data.items():
        v.setdefault('country', key)
        v.setdefault('label', key.upper())
        v['email'] = v.get('email', '')
        v['pass'] = v.get('pass', '')
        v['home'] = os.path.expanduser(v.get('home') or '~')
    return data


REGIONS = _load_regions()
DEFAULT_REGION = env('DEFAULT_REGION') or next(iter(REGIONS))


def norm_region(r):
    return r if r in REGIONS else DEFAULT_REGION


# --- Secret redaction ---
# Everything that can reach the web (job logs, job error fields, API error
# strings) is passed through sanitize() first. The web front-end — including the
# public /logs page reachable through the Cloudflare tunnel — must never contain
# Apple ID emails or passwords. Full, unredacted output still goes to the local
# server.log (stdout), which never leaves this machine.
_SECRETS = []
for _acct in REGIONS.values():
    _SECRETS.extend([_acct['email'], _acct['pass']])
_SECRETS = [s for s in set(_SECRETS) if s]
# Any email address, in case an unexpected account/name shows up.
_EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')


def sanitize(text):
    if text is None:
        return None
    s = str(text)
    for secret in _SECRETS:
        s = s.replace(secret, '[redacted]')
    s = _EMAIL_RE.sub('[redacted]', s)
    return s
try:
    LOCAL_USER = env('MAC_USER') or os.environ.get('SUDO_USER') or os.environ.get('USER') or 'root'
    LOCAL_UID = subprocess.run(['id', '-u', LOCAL_USER], capture_output=True, text=True, timeout=5).stdout.strip() or str(os.getuid())
except Exception:
    LOCAL_UID = str(os.getuid())


def safe_run(cmd, timeout=600, input_text=None, env=None, cwd=None):
    result = subprocess.run(
        cmd, input=input_text.encode() if input_text else None,
        capture_output=True, timeout=timeout, env=env, cwd=cwd
    )
    result.stdout = result.stdout.decode('utf-8', errors='replace') if result.stdout else ''
    result.stderr = result.stderr.decode('utf-8', errors='replace') if result.stderr else ''
    return result


def ipatool_cmd(args, region=DEFAULT_REGION, timeout=600):
    # Global flags must precede the subcommand. --keychain-passphrase forces the
    # ipatool-fixed build to use its encrypted file backend (<HOME>/.ipatool)
    # instead of the macOS login Keychain, so there is no GUI access prompt; that
    # prompt cannot be answered from this headless service and was the cause of
    # the repeated keychain password requests. --non-interactive makes failures
    # return an error instead of blocking on a terminal prompt.
    # `env HOME=<region home>` selects which Apple ID / storefront is used, since
    # ipatool reads its config from $HOME/.ipatool.
    region = norm_region(region)
    home = REGIONS[region]['home']
    ipatool_global = ['--non-interactive', '--keychain-passphrase', SUDO_PASS]
    for attempt in range(3):
        try:
            return safe_run(
                ['sudo', '-S', 'launchctl', 'asuser', LOCAL_UID,
                 'env', 'HOME=' + home, IPATOOL] + ipatool_global + args,
                timeout=timeout, input_text=SUDO_PASS + '\n'
            )
        except OSError as e:
            if attempt < 2:
                time.sleep(2)
                continue
            raise


def unlock_keychain():
    subprocess.run(
        ['security', 'unlock-keychain', '-p', SUDO_PASS, KEYCHAIN_PATH],
        capture_output=True
    )


def ensure_ipatool_auth(region=DEFAULT_REGION):
    region = norm_region(region)
    acct = REGIONS[region]
    result = ipatool_cmd(['auth', 'info'], region=region, timeout=10)
    if result.returncode == 0 and 'success=true' in result.stdout + result.stderr:
        return True
    ipatool_cmd(['auth', 'login', '--email', acct['email'], '-p', acct['pass']], region=region, timeout=30)
    result = ipatool_cmd(['auth', 'info'], region=region, timeout=10)
    return result.returncode == 0


def search_itunes(query, limit=20, country=None):
    params = urllib.parse.urlencode({
        'term': query,
        'entity': 'software',
        'country': country or STORE_COUNTRY,
        'limit': limit
    })
    url = f'https://itunes.apple.com/search?{params}'
    req = urllib.request.Request(url, headers={'User-Agent': 'macOSAppstoreDecrypter/1.0'})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def lookup_itunes(bundle_id, country=None):
    params = urllib.parse.urlencode({'bundleId': bundle_id, 'country': country or STORE_COUNTRY})
    url = f'https://itunes.apple.com/lookup?{params}'
    req = urllib.request.Request(url, headers={'User-Agent': 'macOSAppstoreDecrypter/1.0'})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read())
        if data.get('resultCount', 0) > 0:
            return data['results'][0]
    return None


def resolve_version(bundle_id, region=DEFAULT_REGION):
    """Get the app's version string, falling back across storefronts (the app may
    be delisted in the account's region → no version there). Returns 'unknown'."""
    countries, seen = [REGIONS.get(region, {}).get('country', STORE_COUNTRY), 'us', 'jp', 'gb', 'sg'], set()
    for c in countries:
        if not c or c in seen:
            continue
        seen.add(c)
        try:
            info = lookup_itunes(bundle_id, country=c)
            if info and info.get('version'):
                return info['version']
        except Exception:
            pass
    return 'unknown'


def resolve_app_id(bundle_id, region=DEFAULT_REGION):
    """Resolve a bundle id to its numeric App Store id (adamId). The adamId is
    global, so if the app was delisted from the account's storefront we can still
    find it via another store — then `ipatool download --app-id` can fetch it
    (owned apps re-download even when delisted). Returns int id or None."""
    countries, seen = [REGIONS.get(region, {}).get('country', STORE_COUNTRY), 'us', 'jp', 'gb', 'sg'], set()
    for c in countries:
        if not c or c in seen:
            continue
        seen.add(c)
        try:
            info = lookup_itunes(bundle_id, country=c)
            if info and info.get('trackId'):
                return int(info['trackId'])
        except Exception:
            pass
    return None


def filter_results(results, region=DEFAULT_REGION):
    region = norm_region(region)
    conn = get_db()
    whitelist = set(
        r['bundle_id'] for r in conn.execute('SELECT bundle_id FROM whitelisted_apps').fetchall()
    )
    pass  # thread-local conn, no close

    filtered = []
    for r in results.get('results', []):
        bundle_id = r.get('bundleId', '')
        price = r.get('price', 0)
        genres = r.get('genres', [])

        if 'Apple Arcade' in genres:
            continue
        # Paid apps are kept in results (previously hidden). If the logged-in
        # account already owns one, ipatool can download it; if not, the download
        # fails cleanly. This lets the user grab paid apps they've purchased.

        # Check blacklist — include in results but mark blocked
        blocked = BLACKLIST.get(bundle_id, '')
        if not blocked:
            for prefix, msg in BLACKLIST_PREFIXES.items():
                if bundle_id.startswith(prefix):
                    blocked = msg
                    break

        conn = get_db()
        cached = conn.execute(
            'SELECT version FROM cached_ipas WHERE bundle_id = ? ORDER BY decrypted_at DESC LIMIT 1',
            (bundle_id,)
        ).fetchone()
        pass  # thread-local conn, no close

        store_version = r.get('version', '')
        cached_version = cached['version'] if cached else None
        version_match = cached_version == store_version if cached_version else False

        filtered.append({
            'bundle_id': bundle_id,
            'name': r.get('trackName', ''),
            'icon_url': r.get('artworkUrl100', ''),
            'version': store_version,
            'size_bytes': r.get('fileSizeBytes', 0),
            'seller': r.get('sellerName', ''),
            'price': price,
            'is_whitelisted': bundle_id in whitelist,
            'is_cached': version_match,
            'cached_version': cached_version,
            'blocked': blocked,
        })
    return filtered


# --- Repeated-failure guard: if an app keeps failing, temporarily block
# re-requests so users stop hammering a hopeless app. ---
FAIL_THRESHOLD = 3      # this many failures...
FAIL_WINDOW = 1800      # ...within 30 min...
FAIL_COOLDOWN = 1800    # ...then block that app for 30 min
_fail_lock = threading.Lock()
_fails = {}  # "region:bundle" -> {count, ts, until}


def _fk(bundle_id, region):
    return f'{region}:{bundle_id}'


def note_failure(bundle_id, region):
    if not bundle_id:
        return
    now = time.time()
    with _fail_lock:
        e = _fails.get(_fk(bundle_id, region))
        if not e or now - e['ts'] > FAIL_WINDOW:
            e = {'count': 0, 'ts': now, 'until': 0}
        e['count'] += 1
        e['ts'] = now
        if e['count'] >= FAIL_THRESHOLD:
            e['until'] = now + FAIL_COOLDOWN
        _fails[_fk(bundle_id, region)] = e


def clear_failure(bundle_id, region):
    with _fail_lock:
        _fails.pop(_fk(bundle_id, region), None)


def fail_blocked_until(bundle_id, region):
    """Cooldown-end timestamp if this app is temporarily blocked, else 0."""
    now = time.time()
    with _fail_lock:
        e = _fails.get(_fk(bundle_id, region))
        if e and e.get('until', 0) > now:
            return e['until']
    return 0


def job_log(job_id, msg):
    # Full detail to the local-only server log; redacted copy to the web-visible
    # job log.
    try:
        print(f'[job {job_id[:8]}] {msg}', flush=True)
    except Exception:
        pass
    with job_lock:
        if job_id in jobs:
            jobs[job_id]['logs'].append(f'[{time.strftime("%H:%M:%S")}] {sanitize(msg)}')
            jobs[job_id]['updated_at'] = int(time.time())


def job_update(job_id, status, detail=None, error=None):
    fail_bid = fail_reg = None
    with job_lock:
        if job_id in jobs:
            jobs[job_id]['status'] = status
            jobs[job_id]['detail'] = sanitize(detail)
            jobs[job_id]['error'] = sanitize(error)
            jobs[job_id]['updated_at'] = int(time.time())
            if status == 'failed':
                fail_bid = jobs[job_id].get('bundle_id')
                fail_reg = jobs[job_id].get('region', DEFAULT_REGION)
    if fail_bid:
        note_failure(fail_bid, fail_reg)


def download_phase(job_id, bundle_id, app_name, region=DEFAULT_REGION):
    """Runs immediately in its own thread. Downloads the IPA, then queues decrypt."""
    region = norm_region(region)
    log = lambda msg: job_log(job_id, msg)
    update = lambda status, detail=None, error=None: job_update(job_id, status, detail, error)

    download_semaphore.acquire()
    try:
        log(f'Starting pipeline for {app_name} ({bundle_id}) [{region}]')

        # Check cache
        conn = get_db()
        cached = conn.execute(
            'SELECT * FROM cached_ipas WHERE bundle_id = ? ORDER BY decrypted_at DESC LIMIT 1',
            (bundle_id,)
        ).fetchone()

        if cached and Path(cached['file_path']).exists():
            conn.execute('UPDATE cached_ipas SET last_requested = ? WHERE id = ?',
                        (int(time.time()), cached['id']))
            conn.commit()
            log(f'Found cached IPA')
            with job_lock:
                jobs[job_id]['status'] = 'completed'
                jobs[job_id]['file_path'] = cached['file_path']
                jobs[job_id]['updated_at'] = int(time.time())
            clear_failure(bundle_id, region)
            return

        log(f'Authenticating ipatool ({region})...')
        if ensure_ipatool_auth(region):
            log('ipatool authenticated')
        else:
            log('ipatool auth failed — attempting anyway')

        # Purchase state is per-account, so it is keyed per region.
        purchase_key = f'{region}:{bundle_id}'

        # Downloaded IPAs are namespaced by region so the same bundle id in two
        # storefronts does not collide on disk.
        dl_dir = IPA_DIR / region / bundle_id
        dl_dir.mkdir(parents=True, exist_ok=True)
        dl_path = dl_dir / f'{bundle_id}.ipa'

        # Expected download size (from the App Store) — denominator for the % bar.
        try:
            _info = lookup_itunes(bundle_id, country=REGIONS[region]['country'])
            expected_size = int(_info.get('fileSizeBytes') or 0) if _info else 0
        except Exception:
            expected_size = 0

        def do_purchase():
            update('purchasing', f'Acquiring license for {app_name}...')
            log(f'Purchasing {bundle_id}...')
            try:
                r = ipatool_cmd(['purchase', '--bundle-identifier', bundle_id], region=region, timeout=30)
                if r.returncode == 0:
                    log('License acquired')
                else:
                    log(f'Purchase exit {r.returncode} — trying download anyway')
            except Exception:
                log('Purchase error — trying download anyway')

        def do_download():
            update('downloading', f'Downloading {app_name}...')
            log(f'Downloading {bundle_id}...')
            dl_path.unlink(missing_ok=True)

            # Live progress: a background thread watches how much has landed in
            # dl_dir and reports percent + speed into the job (shown on the web).
            stop = threading.Event()

            def _monitor():
                last_b, last_t = 0, time.time()
                max_pct = 0
                while not stop.wait(1.0):
                    cur = 0
                    try:
                        for f in dl_dir.rglob('*'):
                            if f.is_file():
                                cur += f.stat().st_size
                    except Exception:
                        cur = 0
                    now = time.time()
                    dt = now - last_t
                    # Clamp to >= 0: the file size can briefly dip when ipatool
                    # renames its temp file, which would otherwise show a negative
                    # speed / a backwards percentage.
                    spd = max(0.0, (cur - last_b) / dt) if dt > 0 else 0
                    last_b, last_t = cur, now
                    spd_txt = f'{spd / 1048576:.1f} MB/s'
                    with job_lock:
                        if job_id not in jobs:
                            continue
                        if expected_size > 0:
                            max_pct = max(max_pct, min(99, int(cur * 100 / expected_size)))
                            jobs[job_id]['progress'] = max_pct
                            jobs[job_id]['detail'] = f'Downloading {app_name}... {max_pct}% · {spd_txt}'
                        else:
                            jobs[job_id]['progress'] = None
                            jobs[job_id]['detail'] = f'Downloading {app_name}... {cur / 1048576:.1f} MB · {spd_txt}'
                        jobs[job_id]['speed'] = spd_txt
                        jobs[job_id]['updated_at'] = int(time.time())

            mon = threading.Thread(target=_monitor, daemon=True)
            mon.start()
            try:
                r = ipatool_cmd(['download', '--bundle-identifier', bundle_id, '-o', str(dl_path)], region=region, timeout=600)
                # If the app was delisted from this account's storefront the
                # bundle lookup fails ("app not found"), but an OWNED app can
                # still be re-downloaded by its numeric id. Resolve the adamId
                # (global) via another store and retry with --app-id.
                if r.returncode != 0 and 'not found' in (r.stdout + r.stderr).lower():
                    aid = resolve_app_id(bundle_id, region)
                    if aid:
                        log(f'{bundle_id} not in {region} store — retrying by app-id {aid} (owned app)')
                        dl_path.unlink(missing_ok=True)
                        r = ipatool_cmd(['download', '--app-id', str(aid), '--purchase', '-o', str(dl_path)], region=region, timeout=600)
            finally:
                stop.set()
                mon.join(timeout=2)
            if r.returncode == 0 and dl_path.exists():
                with job_lock:
                    if job_id in jobs:
                        jobs[job_id]['progress'] = 100
            if r.stdout.strip():
                log(f'ipatool: {r.stdout.strip()}')
            if r.stderr.strip():
                log(f'ipatool: {r.stderr.strip()}')
            return r

        # DOWNLOAD-FIRST: try downloading directly. The account already owns most
        # apps (a free app only needs to be "purchased"/licensed ONCE ever), so a
        # direct download usually just works. Only acquire a license (purchase)
        # if the download actually reports it's missing — this stops us from
        # re-"purchasing" the same free app on every request, which was spamming
        # Apple and getting the account flagged.
        result = do_download()
        rerr = (result.stdout + result.stderr).lower()
        needs_license = result.returncode != 0 and not dl_path.exists() and \
            ('license' in rerr or 'not purchased' in rerr or 'redownload' in rerr)
        if needs_license:
            log('Chưa có license cho app này — acquiring license rồi tải lại (chỉ 1 lần)')
            do_purchase()
            result = do_download()

        if result.returncode != 0:
            stderr = result.stderr.strip() if result.stderr else 'Unknown error'
            if 'price' in stderr.lower() or 'paid' in stderr.lower():
                log('FAILED: Paid app')
                update('failed', error='This is a paid app and cannot be downloaded.')
                shutil.rmtree(dl_dir, ignore_errors=True)
                return
            elif not dl_path.exists() or dl_path.stat().st_size < 1024:
                log(f'FAILED: {stderr}')
                update('failed', error='Download failed. The app may be unavailable in this region.')
                shutil.rmtree(dl_dir, ignore_errors=True)
                return

        if not dl_path.exists():
            log('FAILED: IPA file not found')
            update('failed', error='Download completed but IPA file not found.')
            shutil.rmtree(dl_dir, ignore_errors=True)
            return

        # Verify zip
        verify = safe_run(['unzip', '-t', str(dl_path)], timeout=300)
        if verify.returncode != 0:
            log('IPA corrupt — retrying download')
            dl_path.unlink(missing_ok=True)
            result = do_download()
            if not dl_path.exists():
                log('FAILED: Retry produced no file')
                update('failed', error='Download failed after retry.')
                shutil.rmtree(dl_dir, ignore_errors=True)
                return
            verify = safe_run(['unzip', '-t', str(dl_path)], timeout=300)
            if verify.returncode != 0:
                log('FAILED: IPA still corrupt')
                update('failed', error='Downloaded IPA is corrupt.')
                shutil.rmtree(dl_dir, ignore_errors=True)
                return
            log('Retry succeeded')

        # Mark purchased
        conn = get_db()
        conn.execute('INSERT OR REPLACE INTO purchased_apps (bundle_id, purchased_at) VALUES (?, ?)',
                    (purchase_key, int(time.time())))
        conn.commit()

        file_size_mb = dl_path.stat().st_size / (1024 * 1024)
        log(f'Download complete ({file_size_mb:.1f} MB)')

        # Queue for decrypt
        update('waiting_decrypt', f'Waiting for decrypt slot...')
        log('Queued for decryption')
        decrypt_queue.put((job_id, bundle_id, app_name, str(dl_path), region))

    except Exception as e:
        log(f'EXCEPTION: {str(e)}')
        update('failed', error='Something went wrong. Please try again.')
        # Cleanup on download failure
        dl_dir = IPA_DIR / region / bundle_id
        if dl_dir.exists():
            shutil.rmtree(dl_dir, ignore_errors=True)
    finally:
        download_semaphore.release()


# Google apps have huge encrypted binaries that make the normal "decrypt every
# Mach-O" pass run out of memory (mremap_encrypted ENOMEM). For these we decrypt
# ONLY the main app executable (frameworks/plugins are left as-is) and graft it
# back into the full app — which still runs after re-signing.
GOOGLE_PREFIX = 'com.google.'
FREE_RAM_SCRIPT = str(SRC_DIR / 'free-ram.sh')


def main_binary_only_decrypt(dl_path, decrypted_path, log):
    """Decrypt ONLY the app's main executable, then repackage the full app with
    frameworks/plugins copied unchanged (still encrypted). Used for Google apps
    and as an automatic fallback whenever a full decrypt hits mremap OOM.
    Returns a CompletedProcess-like object whose .returncode/.stderr mirror the
    failing step so the caller's OOM handling works. On success decrypted_path
    is written."""
    work = dl_path.parent / 'gwork'
    shutil.rmtree(work, ignore_errors=True)
    full = work / 'full'
    full.mkdir(parents=True)
    try:
        # 1. extract full IPA
        r = safe_run(['unzip', '-q', str(dl_path), '-d', str(full)], timeout=300)
        if r.returncode != 0:
            return r
        app_dir = next((full / 'Payload').glob('*.app'))
        exe = safe_run(['/usr/libexec/PlistBuddy', '-c', 'Print :CFBundleExecutable',
                        str(app_dir / 'Info.plist')]).stdout.strip()
        log(f'Main-binary-only mode: decrypting {app_dir.name}/{exe} (frameworks left as-is)')

        # 2. minimal copy of the app with frameworks/plugins/watch stripped
        min_app = work / 'min' / 'Payload' / app_dir.name
        min_app.parent.mkdir(parents=True)
        shutil.copytree(app_dir, min_app, symlinks=True)
        for sub in ('Frameworks', 'PlugIns', 'Watch'):
            shutil.rmtree(min_app / sub, ignore_errors=True)
        min_ipa = work / 'min.ipa'
        safe_run(['zip', '-q', '-r', '-0', '-X', str(min_ipa), 'Payload'],
                 cwd=str(work / 'min'), timeout=300)

        # 3. free RAM, then decrypt just the main binary via unfair
        safe_run([FREE_RAM_SCRIPT], timeout=60)
        dec_min = work / 'min_dec.ipa'
        r = safe_run([UNFAIR, 'package', '--input', str(min_ipa), '--output', str(dec_min), '--verbose'], timeout=900)
        for line in (r.stdout + r.stderr).strip().split('\n'):
            if line.strip():
                log(f'unfair: {line.strip()}')
        if r.returncode != 0 or not dec_min.exists():
            return r  # OOM/failure — caller retries

        # 4. graft decrypted main binary back into the full app tree
        dec_ext = work / 'dec'
        dec_ext.mkdir()
        safe_run(['unzip', '-q', str(dec_min), '-d', str(dec_ext)], timeout=300)
        dec_app = next((dec_ext / 'Payload').glob('*.app'))
        shutil.copy2(dec_app / exe, app_dir / exe)

        # 5. repackage the FULL app (main decrypted, frameworks untouched)
        decrypted_path.unlink(missing_ok=True)
        z = safe_run(['zip', '-q', '-r', '-0', '-X', str(decrypted_path), 'Payload'],
                     cwd=str(full), timeout=600)
        return z
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run_decrypt(job_id, bundle_id, app_name, dl_path_str, region=DEFAULT_REGION):
    """Runs in decrypt worker. Only the CPU-heavy decrypt step."""
    log = lambda msg: job_log(job_id, msg)
    update = lambda status, detail=None, error=None: job_update(job_id, status, detail, error)
    dl_path = Path(dl_path_str)
    slot_acquired = False

    # unfair already isolates every run in its own unique dir
    # ($TMPDIR/unfair/<uuid>) inside the macOS per-user temp, and it REQUIRES its
    # files to stay under that per-user temp — so we must NOT redirect TMPDIR.
    # Concurrent decrypts are safe: each unfair run gets a fresh uuid dir, and
    # each app's input/output live in its own region/bundle folder → no overlap.

    is_google = bundle_id.startswith(GOOGLE_PREFIX)
    google_locked = False

    try:
        dl_dir = dl_path.parent
        decrypted_path = dl_dir / f'{bundle_id}_decrypted.ipa'

        # Google apps: only one at a time (they need lots of RAM). Take this
        # exclusive lock BEFORE a decrypt slot to avoid holding a slot while idle.
        if is_google:
            update('decrypting', 'Waiting (Google app runs one at a time)...')
            log('Google app — waiting for exclusive decrypt slot...')
            google_lock.acquire()
            google_locked = True

        update('decrypting', 'Waiting for a decrypt slot...')
        log('Waiting for a decrypt slot (RAM-aware, up to %d at once)...' % DECRYPT_HARD_CAP)
        acquire_decrypt_slot(log)
        slot_acquired = True
        log('Decrypt slot acquired')
        update('decrypting', f'Decrypting {app_name}...')

        ATTEMPTS = 5
        # Google apps go straight to main-binary-only (their full decrypt always
        # OOMs). Any other app tries a FULL decrypt first and falls back to
        # main-binary-only automatically the moment it hits mremap OOM.
        use_main_only = is_google
        for attempt in range(ATTEMPTS):
            safe_run(['sudo', '-S', 'purge'], timeout=10, input_text=SUDO_PASS + '\n')
            mode = 'main-binary-only' if use_main_only else 'full'
            log(f'Decrypting {dl_path.name} [{mode}]...' if attempt == 0 else f'Retry {attempt} [{mode}] after purge...')
            decrypted_path.unlink(missing_ok=True)
            if use_main_only:
                result = main_binary_only_decrypt(dl_path, decrypted_path, log)
            else:
                result = safe_run([UNFAIR, 'package', '--input', str(dl_path), '--output', str(decrypted_path), '--verbose'], timeout=900)
                if result.stdout.strip():
                    for line in result.stdout.strip().split('\n'):
                        log(f'unfair: {line}')
                if result.stderr.strip():
                    for line in result.stderr.strip().split('\n'):
                        log(f'unfair err: {line}')

            if result.returncode == 0 and decrypted_path.exists():
                break

            stderr = result.stderr.strip() if result.stderr else ''
            oom = ('Cannot allocate memory' in stderr) or (result.returncode == -9)

            # OOM on a FULL decrypt → switch to main-binary-only and retry now.
            if oom and not use_main_only:
                log('mremap OOM on full decrypt → switching to MAIN BINARY ONLY (frameworks left encrypted)')
                update('decrypting', f'Decrypting {app_name} (main binary only)...')
                use_main_only = True
                continue
            if oom and attempt < ATTEMPTS - 1:
                wait = 15 * (attempt + 1)
                log(f'Out of memory — waiting {wait}s for RAM to free, then retrying...')
                time.sleep(wait)
                continue
            elif oom:
                log('FAILED: not enough memory to decrypt this app')
                update('failed', error='App quá lớn so với RAM trống — thử lại lúc máy rảnh.')
                shutil.rmtree(dl_dir, ignore_errors=True)
                log('Cleaned up leftover files')
                return
            else:
                log(f'FAILED: Decryption exited with code {result.returncode}')
                update('failed', error='Decryption failed. Please try again.')
                shutil.rmtree(dl_dir, ignore_errors=True)
                log('Cleaned up leftover files')
                return

        if not decrypted_path.exists():
            log('FAILED: Decrypted IPA not found')
            update('failed', error='Decryption completed but output file not found.')
            shutil.rmtree(dl_dir, ignore_errors=True)
            log('Cleaned up leftover files')
            return

        # Strip App Store cruft the user doesn't want: the root iTunesMetadata.plist
        # and the META-INF/ folder (added by the store on download). zip -d is
        # in-place; harmless (rc 12) if they aren't present (e.g. main-only path).
        safe_run(['zip', '-d', str(decrypted_path), 'iTunesMetadata.plist', 'META-INF*'], timeout=180)
        log('Stripped iTunesMetadata.plist + META-INF')

        dec_size_mb = decrypted_path.stat().st_size / (1024 * 1024)
        log(f'Decryption complete ({dec_size_mb:.1f} MB)')

        dl_path.unlink(missing_ok=True)
        log('Cleaned up encrypted IPA')

        version = resolve_version(bundle_id, region)
        log(f'App version: {version}')

        file_size = decrypted_path.stat().st_size
        now = int(time.time())
        conn = get_db()
        conn.execute('''
            INSERT OR REPLACE INTO cached_ipas
            (bundle_id, app_name, version, file_path, file_size, decrypted_at, last_requested, region)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (bundle_id, app_name, version, str(decrypted_path), file_size, now, now, region))
        conn.commit()
        log('Cached in database. Ready for download.')

        with job_lock:
            jobs[job_id]['status'] = 'completed'
            jobs[job_id]['file_path'] = str(decrypted_path)
            jobs[job_id]['updated_at'] = now
        clear_failure(bundle_id, region)

    except Exception as e:
        log(f'EXCEPTION: {str(e)}')
        update('failed', error='Something went wrong. Please try again.')
        dl_dir = Path(dl_path_str).parent
        shutil.rmtree(dl_dir, ignore_errors=True)
        log('Cleaned up leftover files')
    finally:
        if slot_acquired:
            release_decrypt_slot()
        if google_locked:
            google_lock.release()


JOB_TTL_SEC = 1800  # auto-remove finished jobs from the in-memory log 30 min after they end


def cleanup_jobs():
    """Drop finished jobs 30 min after completion so the /logs page stays small
    (it was growing unbounded and became too heavy to open on mobile)."""
    while True:
        time.sleep(120)
        try:
            now = int(time.time())
            with job_lock:
                for jid in list(jobs.keys()):
                    j = jobs[jid]
                    age = now - j.get('updated_at', j.get('created_at', now))
                    finished = j['status'] in ('completed', 'failed')
                    # finished jobs: 30 min; anything (incl. stuck): 2 h hard cap
                    if (finished and age > JOB_TTL_SEC) or age > 7200:
                        del jobs[jid]
        except Exception:
            pass


def cleanup_cache():
    while True:
        time.sleep(600)
        try:
            now = int(time.time())
            cutoff = now - (CACHE_TTL_DAYS * 86400)
            conn = get_db()
            expired = conn.execute(
                'SELECT * FROM cached_ipas WHERE last_requested < ?', (cutoff,)
            ).fetchall()
            for row in expired:
                Path(row['file_path']).unlink(missing_ok=True)
                conn.execute('DELETE FROM cached_ipas WHERE id = ?', (row['id'],))
            conn.commit()

            stat = shutil.disk_usage('/')
            free_gb = stat.free / (1024**3)
            while free_gb < DISK_RESERVE_GB:
                oldest = conn.execute(
                    'SELECT * FROM cached_ipas ORDER BY last_requested ASC LIMIT 1'
                ).fetchone()
                if not oldest:
                    break
                Path(oldest['file_path']).unlink(missing_ok=True)
                conn.execute('DELETE FROM cached_ipas WHERE id = ?', (oldest['id'],))
                conn.commit()
                stat = shutil.disk_usage('/')
                free_gb = stat.free / (1024**3)
            pass  # thread-local conn, no close
        except Exception:
            pass


# --- Routes ---

def get_client_ip():
    return request.headers.get('CF-Connecting-IP', request.headers.get('X-Forwarded-For', request.remote_addr))


@app.before_request
def rate_limit_check():
    ip = get_client_ip()
    if request.path == '/health':
        return None
    if not check_rate_limit(ip):
        return jsonify(error='Rate limit exceeded. Please slow down.'), 429


@app.route('/')
def index():
    return Response(get_index_html(), content_type='text/html')


@app.route('/health')
def health():
    return jsonify(status='ok', service='macOSAppstoreDecrypter', paused=intake_paused())


def _lan_only():
    ip = get_client_ip()
    return ip in RATE_WHITELIST_EXACT or ip.startswith(RATE_WHITELIST_PREFIX)


@app.route('/api/v1/pause', methods=['POST', 'GET'])
def api_pause():
    if not (_lan_only() or is_admin_user()):
        return jsonify(error='forbidden'), 403
    try:
        PAUSE_FLAG.touch()
    except Exception as e:
        return jsonify(error=sanitize(str(e))), 500
    return jsonify(paused=True)


@app.route('/api/v1/resume', methods=['POST', 'GET'])
def api_resume():
    if not (_lan_only() or is_admin_user()):
        return jsonify(error='forbidden'), 403
    try:
        PAUSE_FLAG.unlink(missing_ok=True)
    except Exception as e:
        return jsonify(error=sanitize(str(e))), 500
    return jsonify(paused=False)


# ---------- auth endpoints ----------
@app.route('/api/v1/register', methods=['POST'])
def api_register():
    d = request.get_json(force=True)
    email = (d.get('email') or '').strip().lower()
    name = (d.get('name') or '').strip()
    pw = d.get('password') or ''
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify(error='Email không hợp lệ'), 400
    if not name:
        return jsonify(error='Vui lòng nhập tên'), 400
    if len(pw) < 6:
        return jsonify(error='Mật khẩu tối thiểu 6 ký tự'), 400
    conn = get_db()
    if conn.execute('SELECT 1 FROM users WHERE email = ?', (email,)).fetchone():
        return jsonify(error='Email này đã đăng ký'), 409
    conn.execute('INSERT INTO users (email, name, pass_hash, approved, is_admin, created_at) VALUES (?,?,?,0,0,?)',
                 (email, name, _hash_pw(pw), int(time.time())))
    conn.commit()
    return jsonify(ok=True, message='Đăng ký thành công! Tài khoản đang chờ admin duyệt để tải app mới. Trong lúc chờ, bạn vẫn tải được các app đã có sẵn.')


@app.route('/api/v1/login', methods=['POST'])
def api_login():
    d = request.get_json(force=True)
    email = (d.get('email') or '').strip().lower()
    pw = d.get('password') or ''
    u = get_db().execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    if not u or not _verify_pw(pw, u['pass_hash']):
        return jsonify(error='Sai email hoặc mật khẩu'), 401
    session['uid'] = u['id']
    session.permanent = True
    return jsonify(user=user_public(u))


@app.route('/api/v1/logout', methods=['POST', 'GET'])
def api_logout():
    session.pop('uid', None)
    return jsonify(ok=True)


@app.route('/api/v1/me')
def api_me():
    return jsonify(user=user_public(current_user()), open_mode=open_mode_on())


# ---------- admin endpoints ----------
@app.route('/admin')
def admin_page():
    return Response(ADMIN_HTML, content_type='text/html')


@app.route('/api/v1/admin/users')
def api_admin_users():
    if not is_admin_user():
        return jsonify(error='forbidden'), 403
    day = gmt7_today()
    rows = get_db().execute('SELECT * FROM users ORDER BY is_admin DESC, created_at DESC').fetchall()
    out = []
    for u in rows:
        out.append({
            'id': u['id'], 'email': u['email'], 'name': u['name'],
            'approved': bool(u['approved']), 'is_admin': bool(u['is_admin']),
            'used_today': (u['req_count'] if u['req_day'] == day else 0),
            'created_at': u['created_at'],
        })
    return jsonify(users=out, paused=intake_paused(), limit=DAILY_FREE_LIMIT,
                   open_mode=open_mode_on())


@app.route('/api/v1/admin/approve', methods=['POST'])
def api_admin_approve():
    if not is_admin_user():
        return jsonify(error='forbidden'), 403
    d = request.get_json(force=True)
    conn = get_db()
    conn.execute('UPDATE users SET approved = ? WHERE id = ? AND is_admin = 0',
                 (1 if d.get('approved') else 0, d.get('id')))
    conn.commit()
    return jsonify(ok=True)


@app.route('/api/v1/admin/approve-all', methods=['POST'])
def api_admin_approve_all():
    if not is_admin_user():
        return jsonify(error='forbidden'), 403
    conn = get_db()
    cur = conn.execute('UPDATE users SET approved = 1 WHERE is_admin = 0 AND approved = 0')
    conn.commit()
    return jsonify(ok=True, approved=cur.rowcount)


@app.route('/api/v1/admin/open-mode', methods=['POST'])
def api_admin_open_mode():
    if not (_lan_only() or is_admin_user()):
        return jsonify(error='forbidden'), 403
    d = request.get_json(force=True)
    try:
        if d.get('enabled'):
            OPEN_MODE_FLAG.touch()
        else:
            OPEN_MODE_FLAG.unlink(missing_ok=True)
    except Exception as e:
        return jsonify(error=sanitize(str(e))), 500
    return jsonify(ok=True, open_mode=open_mode_on())


@app.route('/api/v1/admin/reset-quota', methods=['POST'])
def api_admin_reset_quota():
    if not is_admin_user():
        return jsonify(error='forbidden'), 403
    d = request.get_json(force=True)
    conn = get_db()
    conn.execute('UPDATE users SET req_count = 0 WHERE id = ?', (d.get('id'),))
    conn.commit()
    return jsonify(ok=True)


@app.route('/api/v1/admin/delete', methods=['POST'])
def api_admin_delete():
    if not is_admin_user():
        return jsonify(error='forbidden'), 403
    d = request.get_json(force=True)
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id = ? AND is_admin = 0', (d.get('id'),))
    conn.commit()
    return jsonify(ok=True)


ADMIN_HTML = '''<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>macOSAppstoreDecrypter · admin</title><style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#09090b;color:#e4e4e7;font-family:-apple-system,system-ui,sans-serif;font-size:.85rem;padding:1rem}
h1{font-size:1.1rem;margin-bottom:1rem}
.card{background:#18181b;border:1px solid #27272a;border-radius:12px;padding:1rem;max-width:760px;margin:0 auto 1rem}
input{width:100%;padding:.6rem;border-radius:8px;border:1px solid #3f3f46;background:#0a0a0a;color:#e4e4e7;margin-bottom:.6rem}
.btn{padding:.45rem .8rem;border:1px solid #3f3f46;border-radius:8px;background:#18181b;color:#e4e4e7;cursor:pointer;font-size:.8rem}
.btn.primary{background:#2563eb;border-color:#2563eb}.btn.warn{background:#7c2d12;border-color:#9a3412}
.btn.ok{background:#14532d;border-color:#166534}.btn.mini{padding:.25rem .5rem;font-size:.72rem;margin-left:.25rem}
table{width:100%;border-collapse:collapse;margin-top:.5rem}
th,td{text-align:left;padding:.5rem .4rem;border-bottom:1px solid #27272a;font-size:.78rem}
th{color:#71717a;font-weight:600}
.pill{padding:.12rem .5rem;border-radius:99px;font-size:.68rem;font-weight:600}
.pill.y{background:#052e16;color:#4ade80}.pill.n{background:#422006;color:#f59e0b}.pill.a{background:#1e3a5f;color:#60a5fa}
.err{color:#f87171;font-size:.8rem;margin-bottom:.5rem}
.row{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}
.grow{flex:1}.muted{color:#71717a}
</style></head><body>
<h1>🛠️ macOSAppstoreDecrypter admin</h1>
<div id=app class=card>đang tải…</div>
<script>
async function j(u,o){const r=await fetch(u,o||{});return await r.json()}
function esc(s){return (s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
async function refresh(){
  const me=(await j('/api/v1/me')).user;
  if(!me||!me.is_admin){return renderLogin('')}
  const d=await j('/api/v1/admin/users');
  renderDash(d);
}
function renderLogin(err){
  document.getElementById('app').innerHTML=
    `<h3 style="margin-bottom:.8rem">Đăng nhập admin</h3>`+
    (err?`<div class=err>${esc(err)}</div>`:``)+
    `<input id=e placeholder=Email autocomplete=username>`+
    `<input id=p type=password placeholder="Mật khẩu" autocomplete=current-password>`+
    `<button class="btn primary" onclick=doLogin()>Đăng nhập</button>`;
}
async function doLogin(){
  const email=document.getElementById('e').value.trim(),password=document.getElementById('p').value;
  const r=await j('/api/v1/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password})});
  if(r.error)return renderLogin(r.error);
  if(!r.user||!r.user.is_admin)return renderLogin('Tài khoản này không phải admin');
  refresh();
}
function renderDash(d){
  const paused=d.paused, open=d.open_mode;
  let h=`<div class=row><div class=grow><b>Trạng thái web:</b> ${paused?'<span class="pill n">ĐANG PAUSE</span>':'<span class="pill y">ĐANG CHẠY</span>'}</div>`+
    `<button class="btn ${paused?'ok':'warn'}" onclick="togglePause(${paused})">${paused?'▶ Mở lại (resume)':'⏸ Tạm dừng (pause)'}</button>`+
    `<button class=btn onclick="fetch('/api/v1/logout',{method:'POST'}).then(()=>location.reload())">Thoát</button></div>`;
  h+=`<div class=row style="margin-top:.7rem;padding-top:.7rem;border-top:1px solid #27272a"><div class=grow><b>Chế độ truy cập:</b><br>`+
    (open?'<span class="pill a">🔓 MỞ TOÀN BỘ — ai cũng decrypt KHÔNG giới hạn, không cần đăng nhập</span>'
         :`<span class="pill y">🔒 Giới hạn ${d.limit} app/ngày mỗi user · cần đăng nhập + được duyệt</span>`)+`</div>`+
    `<button class="btn ${open?'warn':'primary'}" onclick="toggleOpen(${open})">${open?'↩ Về chế độ '+d.limit+' app/ngày':'🔓 Mở toàn bộ'}</button></div>`;
  h+=`<div class=row style="margin-top:.6rem"><div class=grow class=muted>Người dùng đã đăng ký — duyệt để họ tải được app mới${open?' (đang MỞ nên ai cũng tải được).':'.'}</div>`+
    `<button class="btn ok" onclick="approveAll()">✓ Duyệt tất cả</button></div>`;
  h+=`<table><tr><th>Email</th><th>Tên</th><th>Hôm nay</th><th>Trạng thái</th><th></th></tr>`;
  for(const u of d.users){
    const st=u.is_admin?'<span class="pill a">admin</span>':(u.approved?'<span class="pill y">đã duyệt</span>':'<span class="pill n">chờ duyệt</span>');
    let act='';
    if(!u.is_admin){
      act=(u.approved?`<button class="btn mini warn" onclick="approve(${u.id},false)">Bỏ duyệt</button>`
                     :`<button class="btn mini ok" onclick="approve(${u.id},true)">Duyệt</button>`)+
          `<button class="btn mini" onclick="resetQ(${u.id})">Reset lượt</button>`+
          `<button class="btn mini warn" onclick="del(${u.id},'${esc(u.email)}')">Xoá</button>`;
    }
    h+=`<tr><td>${esc(u.email)}</td><td>${esc(u.name)}</td><td>${u.used_today}/${u.is_admin?'∞':d.limit}</td><td>${st}</td><td style="text-align:right">${act}</td></tr>`;
  }
  h+=`</table>`;
  document.getElementById('app').innerHTML=h;
}
async function togglePause(cur){await j(cur?'/api/v1/resume':'/api/v1/pause',{method:'POST'});refresh()}
async function toggleOpen(cur){await j('/api/v1/admin/open-mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:!cur})});refresh()}
async function approveAll(){if(!confirm('Duyệt tất cả tài khoản đang chờ?'))return;const r=await j('/api/v1/admin/approve-all',{method:'POST'});refresh()}
async function approve(id,val){await j('/api/v1/admin/approve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,approved:val})});refresh()}
async function resetQ(id){await j('/api/v1/admin/reset-quota',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});refresh()}
async function del(id,em){if(!confirm('Xoá user '+em+'?'))return;await j('/api/v1/admin/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});refresh()}
refresh();
</script></body></html>'''


try:
    _MEM_TOTAL_GB = int(subprocess.run(['sysctl', '-n', 'hw.memsize'],
                                       capture_output=True, text=True, timeout=5).stdout.strip()) / (1024 ** 3)
except Exception:
    _MEM_TOTAL_GB = 0.0
_NCPU = os.cpu_count() or 1


@app.route('/api/v1/sysstatus')
def api_sysstatus():
    # RAM
    free_gb = _mem_available_gb()  # macOS-style available (incl. reclaimable cache) — matches Activity Monitor
    used_gb = max(0.0, _MEM_TOTAL_GB - free_gb)
    # CPU via load average (instant, no slow `top`)
    try:
        load1 = os.getloadavg()[0]
    except Exception:
        load1 = 0.0
    cpu_pct = min(100, round(load1 / _NCPU * 100))
    # swap
    swap_used_mb = 0.0
    try:
        s = subprocess.run(['sysctl', '-n', 'vm.swapusage'], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r'used\s*=\s*([\d.]+)M', s)
        if m:
            swap_used_mb = float(m.group(1))
    except Exception:
        pass
    # disk
    try:
        du = shutil.disk_usage('/')
        disk_free_gb = du.free / (1024 ** 3)
    except Exception:
        disk_free_gb = 0.0
    # battery % + charging state
    batt_pct, batt_state = None, ''
    try:
        out = subprocess.run(['pmset', '-g', 'batt'], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r'(\d+)%;\s*([A-Za-z ]+)', out)
        if m:
            batt_pct = int(m.group(1))
            batt_state = m.group(2).strip()
    except Exception:
        pass
    # temperature: battery temp via ioreg (no sudo). Root "Temperature" = <1/100 °C>.
    temp_c = None
    try:
        out = subprocess.run(['ioreg', '-r', '-n', 'AppleSmartBattery'], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r'"Temperature" = (\d+)', out)
        if m:
            temp_c = round(int(m.group(1)) / 100.0, 1)
    except Exception:
        pass
    # decrypts running
    with _decrypt_cv:
        running = _decrypt_running
    return jsonify(
        ram_total_gb=round(_MEM_TOTAL_GB, 1),
        ram_free_gb=round(free_gb, 2),
        ram_used_gb=round(used_gb, 2),
        cpu_pct=cpu_pct,
        load1=round(load1, 2),
        ncpu=_NCPU,
        swap_used_mb=round(swap_used_mb),
        disk_free_gb=round(disk_free_gb, 1),
        decrypts_running=running,
        battery_pct=batt_pct,
        battery_state=batt_state,
        temp_c=temp_c,
        paused=intake_paused(),
    )


@app.route('/myip')
def myip():
    return jsonify(
        ip=get_client_ip(),
        cf=request.headers.get('CF-Connecting-IP', ''),
        xff=request.headers.get('X-Forwarded-For', ''),
        remote=request.remote_addr,
        whitelisted=get_client_ip() in RATE_WHITELIST_EXACT or get_client_ip().startswith(RATE_WHITELIST_PREFIX),
    )


@app.route('/api/v1/lookup')
def api_lookup():
    bid = request.args.get('id', '').strip()
    region = norm_region(request.args.get('region', DEFAULT_REGION))
    if not bid:
        return jsonify(results=[])
    cache_key = f'lookup:{region}:{bid}'
    hit = cached_response(cache_key, ttl=300)
    if hit is not None:
        return jsonify(results=hit)
    try:
        info = lookup_itunes(bid, country=REGIONS[region]['country'])
        if not info:
            return jsonify(results=[], error='App not found for this bundle ID')
        conn = get_db()
        cached = conn.execute(
            'SELECT version FROM cached_ipas WHERE bundle_id = ? ORDER BY decrypted_at DESC LIMIT 1',
            (bid,)
        ).fetchone()
        whitelist = set(
            r['bundle_id'] for r in conn.execute('SELECT bundle_id FROM whitelisted_apps').fetchall()
        )
        pass  # thread-local conn, no close
        result = [{
            'bundle_id': bid,
            'name': info.get('trackName', ''),
            'icon_url': info.get('artworkUrl100', ''),
            'version': info.get('version', ''),
            'size_bytes': info.get('fileSizeBytes', 0),
            'seller': info.get('sellerName', ''),
            'price': info.get('price', 0),
            'is_whitelisted': bid in whitelist,
            'is_cached': (cached['version'] == info.get('version', '')) if cached else False,
            'cached_version': cached['version'] if cached else None,
        }]
        set_cache(cache_key, result)
        return jsonify(results=result)
    except Exception as e:
        return jsonify(results=[], error=sanitize(str(e)))


@app.route('/api/v1/search')
def api_search():
    q = request.args.get('q', '').strip()
    region = norm_region(request.args.get('region', DEFAULT_REGION))
    if not q or len(q) < 2:
        return jsonify(results=[])
    cache_key = f'search:{region}:{q.lower()}'
    hit = cached_response(cache_key, ttl=120)
    if hit is not None:
        return jsonify(results=hit)
    try:
        results = search_itunes(q, country=REGIONS[region]['country'])
        filtered = filter_results(results, region)
        set_cache(cache_key, filtered)
        return jsonify(results=filtered)
    except Exception as e:
        return jsonify(results=[], error=sanitize(str(e)))


@app.route('/api/v1/request', methods=['POST'])
def api_request_decrypt():
    data = request.get_json(force=True)
    bundle_id = data.get('bundle_id', '').strip()
    app_name = data.get('app_name', 'Unknown')
    region = norm_region(data.get('region', DEFAULT_REGION))

    force_update = data.get('force', False)

    if not bundle_id:
        return jsonify(error='bundle_id required'), 400

    # Reject anything that isn't a reverse-DNS bundle id (people paste links or
    # app names into the Bundle ID box). App-name mode always sends a real one.
    if not re.match(r'^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$', bundle_id):
        return jsonify(error='Không phải Bundle ID hợp lệ (vd: com.mojang.minecraftpe). Nếu muốn tìm theo tên app, dùng chế độ App Name.'), 400

    if intake_paused():
        return jsonify(error='Đang tạm dừng nhận app mới (bảo trì/nâng cấp). Vui lòng thử lại sau.'), 503

    # Temporarily block apps that keep failing so users stop hammering them.
    bu = fail_blocked_until(bundle_id, region)
    if bu:
        mins = int((bu - time.time()) // 60) + 1
        return jsonify(error=f'App này liên tục lỗi ({FAIL_THRESHOLD}+ lần), tạm dừng thử lại ~{mins} phút nữa. Nếu là app quá lớn/không hỗ trợ thì sẽ không decrypt được.'), 429

    # Check blacklist
    if bundle_id in BLACKLIST:
        return jsonify(error=BLACKLIST[bundle_id]), 403
    for prefix, msg in BLACKLIST_PREFIXES.items():
        if bundle_id.startswith(prefix):
            return jsonify(error=msg), 403

    dl_url = f'/api/v1/download/{bundle_id}?region={region}'

    # Check if cached version matches latest store version
    conn = get_db()
    cached = conn.execute(
        'SELECT * FROM cached_ipas WHERE bundle_id = ? ORDER BY decrypted_at DESC LIMIT 1',
        (bundle_id,)
    ).fetchone()
    pass  # thread-local conn, no close

    if cached and Path(cached['file_path']).exists() and not force_update:
        try:
            info = lookup_itunes(bundle_id, country=REGIONS[region]['country'])
            store_version = info.get('version', '') if info else ''
        except Exception:
            store_version = ''
        if not store_version or cached['version'] == store_version:
            conn = get_db()
            conn.execute(
                'UPDATE cached_ipas SET last_requested = ? WHERE id = ?',
                (int(time.time()), cached['id'])
            )
            conn.commit()
            pass  # thread-local conn, no close
            return jsonify(job_id=None, status='completed',
                           download_url=dl_url)
        else:
            # New version available — remove old cache so pipeline re-downloads
            Path(cached['file_path']).unlink(missing_ok=True)
            conn = get_db()
            conn.execute('DELETE FROM cached_ipas WHERE id = ?', (cached['id'],))
            conn.commit()
            dl_dir = IPA_DIR / region / bundle_id
            if dl_dir.exists():
                shutil.rmtree(dl_dir, ignore_errors=True)

    if force_update and cached:
        Path(cached['file_path']).unlink(missing_ok=True)
        conn = get_db()
        conn.execute('DELETE FROM cached_ipas WHERE id = ?', (cached['id'],))
        conn.commit()
        dl_dir = IPA_DIR / region / bundle_id
        if dl_dir.exists():
            shutil.rmtree(dl_dir, ignore_errors=True)

    with job_lock:
        for jid, j in jobs.items():
            if j['bundle_id'] == bundle_id and j.get('region', DEFAULT_REGION) == region and j['status'] not in ('completed', 'failed'):
                return jsonify(job_id=jid, status=j['status'])

    # --- Auth gate: a NEW decrypt (cache miss / new version / force) normally
    # needs a logged-in, approved user and uses 1 of their daily quota. Cache
    # hits above are served to everyone (incl. anonymous). In OPEN MODE (admin
    # toggle) this gate is lifted entirely: anyone decrypts new apps, unlimited,
    # no login required. ---
    u = current_user()
    _open = open_mode_on()
    _u_admin = bool(u['is_admin']) if u else False
    _unlimited = _open or _u_admin
    _q_day = gmt7_today()
    _q_used = u['req_count'] if (u and u['req_day'] == _q_day) else 0
    if not _open:
        if not u:
            return jsonify(error='Bạn cần đăng nhập để tải app MỚI. (App đã có sẵn thì tải được, không cần đăng nhập.)', need_login=True), 401
        if not _u_admin:
            if not u['approved']:
                return jsonify(error='Tài khoản của bạn đang chờ admin duyệt. Sau khi được duyệt bạn sẽ tải được app mới.'), 403
            if _q_used >= DAILY_FREE_LIMIT:
                return jsonify(error=f'Bạn đã dùng hết {DAILY_FREE_LIMIT} lượt tải app mới hôm nay (reset 0h giờ VN).'), 429

    job_id = str(uuid.uuid4())
    # Count queue position and enforce limit
    with job_lock:
        queue_pos = sum(1 for j in jobs.values() if j['status'] in ('queued', 'purchasing', 'downloading', 'decrypting'))
        if queue_pos >= 10:
            return jsonify(error='Queue is full (10 apps). Please try again later.'), 429
        jobs[job_id] = {
            'bundle_id': bundle_id,
            'app_name': app_name,
            'region': region,
            'status': 'queued',
            'detail': f'In queue (position {queue_pos + 1})',
            'error': None,
            'file_path': None,
            'progress': None,
            'speed': None,
            'logs': [],
            'created_at': int(time.time()),
            'updated_at': int(time.time()),
        }

    # Consume 1 daily quota now that a new decrypt is actually queued (never in
    # open mode, never for admins, never for anonymous open-mode users).
    if not _unlimited and u:
        conn = get_db()
        conn.execute('UPDATE users SET req_count = ?, req_day = ? WHERE id = ?', (_q_used + 1, _q_day, u['id']))
        conn.commit()

    # Download starts immediately in its own thread, decrypt gets queued
    thread = threading.Thread(target=download_phase, args=(job_id, bundle_id, app_name, region), daemon=True)
    thread.start()
    return jsonify(job_id=job_id, status='queued', quota_left=(None if _unlimited else max(0, DAILY_FREE_LIMIT - _q_used - 1)))


@app.route('/api/v1/jobs/<job_id>')
def api_job_status(job_id):
    with job_lock:
        job = jobs.get(job_id)
        if not job:
            return jsonify(error='Job not found'), 404
        region = job.get('region', DEFAULT_REGION)
        resp = {
            'job_id': job_id,
            'bundle_id': job['bundle_id'],
            'app_name': job['app_name'],
            'region': region,
            'status': job['status'],
            'detail': job['detail'],
            'error': job['error'],
            'progress': job.get('progress'),
            'speed': job.get('speed'),
            'logs': list(job.get('logs', [])),
            'download_url': f"/api/v1/download/{job['bundle_id']}?region={region}" if job['status'] == 'completed' else None,
        }
    return jsonify(resp)


@app.route('/api/v1/download/<bundle_id>')
def api_download(bundle_id):
    region = norm_region(request.args.get('region', DEFAULT_REGION))
    ip = get_client_ip()
    skip_limit = ip in RATE_WHITELIST_EXACT or ip.startswith(RATE_WHITELIST_PREFIX)
    if not skip_limit and not user_download_semaphore.acquire(blocking=False):
        return jsonify(error='Server busy — too many concurrent downloads. Try again in a moment.'), 429

    try:
        conn = get_db()
        cached = conn.execute(
            'SELECT * FROM cached_ipas WHERE bundle_id = ? ORDER BY decrypted_at DESC LIMIT 1',
            (bundle_id,)
        ).fetchone()

        if not cached or not Path(cached['file_path']).exists():
            return jsonify(error='File not found'), 404

        conn.execute(
            'UPDATE cached_ipas SET last_requested = ? WHERE id = ?',
            (int(time.time()), cached['id'])
        )
        conn.commit()

        filename = f"{cached['app_name']}_{cached['version']}_decrypted.ipa"
        return send_file(cached['file_path'], as_attachment=True, download_name=filename)
    finally:
        if not skip_limit:
            user_download_semaphore.release()


@app.route('/api/v1/download/<bundle_id>/binaries')
def api_download_binaries(bundle_id):
    import zipfile
    import io

    region = norm_region(request.args.get('region', DEFAULT_REGION))
    if not user_download_semaphore.acquire(blocking=False):
        return jsonify(error='Server busy — too many concurrent downloads. Try again in a moment.'), 429

    try:
        MACHO_MAGICS = {
            b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
            b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
            b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',
        }

        conn = get_db()
        cached = conn.execute(
            'SELECT * FROM cached_ipas WHERE bundle_id = ? ORDER BY decrypted_at DESC LIMIT 1',
            (bundle_id,)
        ).fetchone()

        if not cached or not Path(cached['file_path']).exists():
            return jsonify(error='File not found'), 404

        conn.execute('UPDATE cached_ipas SET last_requested = ? WHERE id = ?',
                    (int(time.time()), cached['id']))
        conn.commit()

        buf = io.BytesIO()
        with zipfile.ZipFile(cached['file_path'], 'r') as ipa:
            with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as out:
                for info in ipa.infolist():
                    if info.is_dir() or info.file_size < 4:
                        continue
                    with ipa.open(info) as f:
                        magic = f.read(4)
                    if magic in MACHO_MAGICS:
                        data = ipa.read(info.filename)
                        name = info.filename.split('/')[-1]
                        parent = '/'.join(info.filename.split('/')[1:-1])
                        out_path = f'{parent}/{name}' if parent else name
                        out.writestr(out_path, data)

        buf.seek(0)
        filename = f"{cached['app_name']}_{cached['version']}_binaries.zip"
        return send_file(buf, as_attachment=True, download_name=filename, mimetype='application/zip')
    except Exception as e:
        return jsonify(error=sanitize(str(e))), 500
    finally:
        user_download_semaphore.release()


@app.route('/api/v1/cache')
def api_cache():
    conn = get_db()
    rows = conn.execute('SELECT * FROM cached_ipas ORDER BY last_requested DESC').fetchall()
    pass  # thread-local conn, no close
    return jsonify(cache=[dict(r) for r in rows])


@app.route('/api/v1/top')
def api_top():
    hit = cached_response('top_apps', ttl=600)
    if hit is not None:
        return jsonify(results=hit)
    try:
        url = f'https://itunes.apple.com/vn/rss/topfreeapplications/limit=30/json'
        req = urllib.request.Request(url, headers={'User-Agent': 'macOSAppstoreDecrypter/1.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        conn = get_db()
        whitelist = set(
            r['bundle_id'] for r in conn.execute('SELECT bundle_id FROM whitelisted_apps').fetchall()
        )

        results = []
        for entry in data.get('feed', {}).get('entry', []):
            bundle_id = entry.get('id', {}).get('attributes', {}).get('im:bundleId', '')
            if not bundle_id:
                continue

            price = 0
            try:
                price = float(entry.get('im:price', {}).get('attributes', {}).get('amount', 0))
            except Exception:
                pass

            blocked = BLACKLIST.get(bundle_id, '')
            if not blocked:
                for prefix, msg in BLACKLIST_PREFIXES.items():
                    if bundle_id.startswith(prefix):
                        blocked = msg
                        break

            if price > 0 and bundle_id not in whitelist:
                continue

            cached = conn.execute(
                'SELECT version FROM cached_ipas WHERE bundle_id = ? ORDER BY decrypted_at DESC LIMIT 1',
                (bundle_id,)
            ).fetchone()

            images = entry.get('im:image', [])
            icon_url = images[-1].get('label', '') if images else ''

            name = entry.get('im:name', {}).get('label', '')
            seller = entry.get('im:artist', {}).get('label', '')

            cached_version = cached['version'] if cached else None

            results.append({
                'bundle_id': bundle_id,
                'name': name,
                'icon_url': icon_url,
                'version': '',
                'size_bytes': 0,
                'seller': seller,
                'price': price,
                'is_whitelisted': bundle_id in whitelist,
                'is_cached': cached is not None,
                'cached_version': cached_version,
                'blocked': blocked,
            })

        set_cache('top_apps', results)
        return jsonify(results=results)
    except Exception as e:
        return jsonify(results=[], error=sanitize(str(e)))


@app.route('/logs')
def logs_page():
    # Cap the payload so /logs stays light on mobile: newest 40 jobs, last 80
    # log lines each. (Old finished jobs are also auto-removed after 30 min.)
    with job_lock:
        ordered = sorted(jobs.items(), key=lambda x: x[1].get('updated_at', x[1]['created_at']), reverse=True)[:40]
        all_jobs = []
        for jid, j in ordered:
            all_jobs.append({
                'job_id': jid,
                'bundle_id': j['bundle_id'],
                'app_name': j['app_name'],
                'status': j['status'],
                'detail': j['detail'],
                'error': j['error'],
                'logs': list(j.get('logs', []))[-80:],
                'created_at': j['created_at'],
            })
    return Response(LOG_PAGE.replace('__JOBS__', json.dumps(all_jobs)), content_type='text/html')


LOG_PAGE = '''<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>macOSAppstoreDecrypter - logs</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'SF Mono','Fira Code',monospace;background:#09090b;color:#a1a1aa;font-size:.75rem;padding:1rem}
h1{font-family:-apple-system,system-ui,sans-serif;font-size:1rem;color:#e4e4e7;margin-bottom:.25rem}
.sub{color:#52525b;font-size:.7rem;margin-bottom:1rem}
.job{margin-bottom:1rem;border:1px solid #27272a;border-radius:8px;overflow:hidden}
.job-head{display:flex;align-items:center;gap:.5rem;padding:.5rem .75rem;background:#18181b;cursor:pointer;user-select:none}
.job-head:hover{background:#1c1c1c}
.badge{padding:.15rem .4rem;border-radius:4px;font-size:.6rem;font-weight:600;text-transform:uppercase}
.badge.queued{background:#27272a;color:#a1a1aa}
.badge.purchasing,.badge.downloading,.badge.decrypting{background:#1e3a5f;color:#60a5fa}
.badge.waiting_decrypt{background:#422006;color:#f59e0b}
.badge.completed{background:#052e16;color:#4ade80}
.badge.failed{background:#450a0a;color:#f87171}
.job-name{flex:1;color:#e4e4e7;font-family:-apple-system,system-ui,sans-serif;font-size:.8rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.job-bid{color:#3f3f46;font-size:.65rem;font-family:'SF Mono',monospace}
.job-time{color:#3f3f46;font-size:.65rem;flex-shrink:0}
.job-logs{padding:.5rem .75rem;max-height:400px;overflow-y:auto;background:#0a0a0a;line-height:1.7;white-space:pre-wrap;word-break:break-all}
.l-ok{color:#4ade80}.l-err{color:#f87171}.l-t{color:#3f3f46}
.error-msg{color:#f87171;padding:.25rem .75rem;background:#1a0505;font-size:.7rem}
.auto{color:#52525b;text-align:center;padding:.5rem;font-size:.65rem}
.statusbar{position:sticky;top:0;z-index:10;background:#111114ee;backdrop-filter:blur(6px);border:1px solid #27272a;border-radius:8px;padding:.5rem .75rem;margin-bottom:1rem;display:flex;flex-wrap:wrap;gap:.4rem 1rem;font-size:.72rem}
.statusbar .m{color:#a1a1aa;white-space:nowrap}.statusbar .m b{color:#e4e4e7;font-weight:600}
.statusbar .bar{display:inline-block;width:64px;height:6px;background:#27272a;border-radius:3px;overflow:hidden;vertical-align:middle;margin-left:.3rem}
.statusbar .bar>i{display:block;height:100%;background:#4ade80;transition:width .5s}
.warn{color:#f59e0b!important}.crit{color:#f87171!important}
@media(max-width:480px){body{padding:.5rem}.job-logs{font-size:.6rem;max-height:300px}}
</style></head><body>
<h1>macOSAppstoreDecrypter logs</h1>
<div id="statusbar" class="statusbar"><span class="m">machine status loading…</span></div>
<div class="sub">Real-time job logs &middot; auto-refreshes every 2s</div>
<div id="jobs"></div>
<div class="auto" id="status">Loading...</div>
<script>
let allJobs=__JOBS__;
const scrollState={};

function render(){
    const el=document.getElementById('jobs');
    if(!allJobs.length){el.innerHTML='<div class="auto">No jobs yet</div>';return}
    // Save scroll positions before re-render
    document.querySelectorAll('.job-logs').forEach(logEl=>{
        const id=logEl.dataset.jid;
        if(id){
            const atBottom=logEl.scrollHeight-logEl.scrollTop-logEl.clientHeight<30;
            scrollState[id]={top:logEl.scrollTop,atBottom:atBottom};
        }
    });
    el.innerHTML=allJobs.map(j=>{
        const d=new Date(j.created_at*1000);
        const t=d.toLocaleTimeString();
        const logs=(j.logs||[]).map(l=>{
            let cls='';
            if(l.includes('FAILED')||l.includes('EXCEPTION')||l.includes('err:'))cls='l-err';
            else if(l.includes('complete')||l.includes('Ready')||l.includes('acquired')||l.includes('Cached')||l.includes('authenticated'))cls='l-ok';
            const m=l.match(/^(\\[[^\\]]+\\]) (.*)$/);
            if(m)return `<span class="l-t">${esc(m[1])}</span> <span class="${cls}">${esc(m[2])}</span>`;
            return `<span class="${cls}">${esc(l)}</span>`;
        }).join('\\n');
        return `<div class="job">
            <div class="job-head">
                <span class="badge ${j.status}">${j.status}</span>
                <span class="job-name">${esc(j.app_name)}</span>
                <span class="job-time">${t}</span>
            </div>
            <div class="job-bid" style="padding:0 .75rem .25rem;background:#18181b">${esc(j.bundle_id)}</div>
            ${j.error?`<div class="error-msg">${esc(j.error)}</div>`:''}
            ${logs?`<div class="job-logs" data-jid="${j.job_id}">${logs}</div>`:''}
        </div>`;
    }).join('');
    // Restore scroll positions — auto-scroll to bottom if user was at bottom
    document.querySelectorAll('.job-logs').forEach(logEl=>{
        const id=logEl.dataset.jid;
        const saved=scrollState[id];
        if(saved&&!saved.atBottom){
            logEl.scrollTop=saved.top;
        }else{
            logEl.scrollTop=logEl.scrollHeight;
        }
    });
}

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
render();

async function poll(){
    try{
        const ids=[...new Set(allJobs.map(j=>j.job_id))];
        // Fetch all known jobs
        for(const id of ids){
            try{
                const r=await fetch('/api/v1/jobs/'+id);
                if(r.ok){
                    const d=await r.json();
                    const idx=allJobs.findIndex(j=>j.job_id===id);
                    if(idx>=0)allJobs[idx]={...allJobs[idx],...d};
                }
            }catch(e){}
        }
        // Check for new jobs in queue
        try{
            const qr=await fetch('/api/v1/queue');
            const qd=await qr.json();
            for(const qi of (qd.queue||[])){
                if(!allJobs.find(j=>j.job_id===qi.job_id)){
                    try{
                        const r=await fetch('/api/v1/jobs/'+qi.job_id);
                        if(r.ok){const d=await r.json();allJobs.unshift(d)}
                    }catch(e){}
                }
            }
        }catch(e){}
        render();
        document.getElementById('status').textContent='Last updated: '+new Date().toLocaleTimeString();
    }catch(e){document.getElementById('status').textContent='Refresh failed'}
}
setInterval(poll,2000);

async function updateStatus(){
    try{
        const s=await (await fetch('/api/v1/sysstatus')).json();
        const ramPct=s.ram_total_gb?Math.round((s.ram_used_gb/s.ram_total_gb)*100):0;
        const ramCls=s.ram_free_gb<1?'crit':(s.ram_free_gb<2?'warn':'');
        const cpuCls=s.cpu_pct>=90?'crit':(s.cpu_pct>=70?'warn':'');
        const battCls=(s.battery_pct!=null&&s.battery_pct<=20&&!/charg/i.test(s.battery_state||''))?'crit':'';
        const battIco=/charg/i.test(s.battery_state||'')?'🔌':'🔋';
        const tempCls=s.temp_c!=null?(s.temp_c>=40?'crit':(s.temp_c>=35?'warn':'')):'';
        const el=document.getElementById('statusbar');
        el.innerHTML=
            `<span class="m ${ramCls}">RAM <b>${s.ram_free_gb.toFixed(1)}</b> GB free / ${s.ram_total_gb} GB`+
            `<span class="bar"><i style="width:${ramPct}%;background:${s.ram_free_gb<1?'#f87171':(s.ram_free_gb<2?'#f59e0b':'#4ade80')}"></i></span></span>`+
            `<span class="m ${cpuCls}">CPU <b>${s.cpu_pct}%</b> (load ${s.load1}/${s.ncpu})</span>`+
            (s.battery_pct!=null?`<span class="m ${battCls}">${battIco} <b>${s.battery_pct}%</b>${s.battery_state?' ('+s.battery_state+')':''}</span>`:``)+
            (s.temp_c!=null?`<span class="m ${tempCls}">🌡️ <b>${s.temp_c}°C</b></span>`:``)+
            `<span class="m">Swap <b>${s.swap_used_mb}</b> MB</span>`+
            `<span class="m">Disk <b>${s.disk_free_gb}</b> GB free</span>`+
            `<span class="m">Decrypting <b>${s.decrypts_running}</b></span>`+
            (s.paused?`<span class="m warn">⏸ PAUSED</span>`:``);
    }catch(e){}
}
updateStatus();
setInterval(updateStatus,4000);
</script></body></html>'''


@app.route('/api/v1/queue')
def api_queue():
    with job_lock:
        active = []
        for jid, j in jobs.items():
            if j['status'] in ('queued', 'purchasing', 'downloading', 'waiting_decrypt', 'decrypting'):
                active.append({
                    'job_id': jid,
                    'bundle_id': j['bundle_id'],
                    'app_name': j['app_name'],
                    'status': j['status'],
                    'detail': j['detail'],
                    'created_at': j['created_at'],
                })
    active.sort(key=lambda x: x['created_at'])
    return jsonify(queue=active, workers=MAX_DECRYPT_WORKERS)


def decrypt_worker(worker_id):
    while True:
        try:
            job_id, bundle_id, app_name, dl_path, region = decrypt_queue.get(timeout=5)
        except queue.Empty:
            continue
        try:
            # Update queue positions for waiting decrypt jobs
            with job_lock:
                waiting = [(jid, j['created_at']) for jid, j in jobs.items() if j['status'] == 'waiting_decrypt']
                waiting.sort(key=lambda x: x[1])
                for i, (jid, _) in enumerate(waiting):
                    jobs[jid]['detail'] = f'Decrypt queue (position {i + 1})'
            run_decrypt(job_id, bundle_id, app_name, dl_path, region)
        except BaseException as e:
            try:
                with job_lock:
                    if jobs.get(job_id, {}).get('status') not in ('completed', 'failed'):
                        jobs[job_id]['status'] = 'failed'
                        jobs[job_id]['error'] = 'Something went wrong. Please try again.'
                        jobs[job_id]['logs'].append(f'[{time.strftime("%H:%M:%S")}] WORKER EXCEPTION: {sanitize(str(e))}')
                        print(f'[job {job_id[:8]}] WORKER EXCEPTION: {str(e)}', flush=True)
            except BaseException:
                pass
        finally:
            try:
                decrypt_queue.task_done()
            except ValueError:
                pass


def start_background_threads():
    cleanup_thread = threading.Thread(target=cleanup_cache, daemon=True)
    cleanup_thread.start()
    jobs_cleanup = threading.Thread(target=cleanup_jobs, daemon=True)
    jobs_cleanup.start()
    rate_cleanup = threading.Thread(target=cleanup_rate_buckets, daemon=True)
    rate_cleanup.start()
    for i in range(MAX_DECRYPT_WORKERS):
        t = threading.Thread(target=decrypt_worker, args=(i,), daemon=True, name=f'decrypt-worker-{i}')
        t.start()


_bg_started = False


def ensure_background_threads():
    global _bg_started
    if not _bg_started:
        _bg_started = True
        init_db()
        unlock_keychain()
        start_background_threads()


ensure_background_threads()

if __name__ == '__main__':
    app.run(host=env('BIND_HOST', '0.0.0.0'), port=int(env('PORT', '6347')), threaded=True)
