import ipaddress
import json
import threading
import time
import urllib.parse
import urllib.request

try:
    from user_agents import parse as parse_user_agent
except ImportError:  # pragma: no cover - deployment installs the dependency.
    parse_user_agent = None


GEOIP_CACHE_TTL_SECS = 6 * 60 * 60
GEOIP_URL = "http://ip-api.com/json/{ip}"
GEOIP_FIELDS = ",".join(
    [
        "status",
        "message",
        "country",
        "countryCode",
        "regionName",
        "city",
        "timezone",
        "isp",
        "org",
        "as",
        "asname",
        "mobile",
        "proxy",
        "hosting",
        "query",
    ]
)

_geoip_cache = {}
_geoip_lock = threading.Lock()


def get_client_ip(req):
    """Return the best client IP from trusted proxy headers or Flask."""
    for raw_ip in _candidate_client_ips(req):
        if _is_public_ip(raw_ip):
            return _normalize_ip(raw_ip)
    raw_ip = next(iter(_candidate_client_ips(req)), "")
    return _normalize_ip(raw_ip) or "unknown"


def get_client_ip_chain(req):
    """Return normalized IPs seen in proxy headers and Flask, preserving order."""
    seen = []
    for raw_ip in _candidate_client_ips(req):
        ip = _normalize_ip(raw_ip)
        if ip and ip not in seen:
            seen.append(ip)
    return seen


def _candidate_client_ips(req):
    forwarded_for = req.headers.get("X-Forwarded-For", "")
    for raw_ip in forwarded_for.split(","):
        raw_ip = raw_ip.strip()
        if raw_ip:
            yield raw_ip

    real_ip = req.headers.get("X-Real-IP", "").strip()
    if real_ip:
        yield real_ip

    raw_ip = (req.remote_addr or "").strip()
    if raw_ip:
        yield raw_ip


def _normalize_ip(raw_ip):
    try:
        return str(ipaddress.ip_address(raw_ip))
    except ValueError:
        return raw_ip.strip()


def lookup_ip_geo(ip):
    """Look up public IP metadata. Failures return an empty dict."""
    if not _is_public_ip(ip):
        return {}

    now = time.time()
    with _geoip_lock:
        cached = _geoip_cache.get(ip)
        if cached and now - cached["time"] < GEOIP_CACHE_TTL_SECS:
            return cached["data"]

    params = urllib.parse.urlencode({"fields": GEOIP_FIELDS})
    url = f"{GEOIP_URL.format(ip=urllib.parse.quote(ip, safe=''))}?{params}"
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception:
        return {}

    if data.get("status") != "success":
        data = {}

    with _geoip_lock:
        _geoip_cache[ip] = {"time": now, "data": data}
        if len(_geoip_cache) > 512:
            _geoip_cache.pop(next(iter(_geoip_cache)))
    return data


def build_registration_notification(username, reg_time, req):
    """Build the Telegram text for a new VPN registration."""
    client_ip = get_client_ip(req)
    ip_chain = get_client_ip_chain(req)
    geo = lookup_ip_geo(client_ip)
    ua = summarize_user_agent(req.user_agent.string or "")

    lines = [
        "\U0001f514 *New VPN registration*",
        "",
        f"\U0001f464 Username: `{_tg_code(username)}`",
        f"\U0001f552 Time: `{_tg_code(reg_time)}`",
        f"\U0001f310 IP: `{_tg_code(client_ip)}`",
    ]

    private_ips = [ip for ip in ip_chain if ip != client_ip and not _is_public_ip(ip)]
    if private_ips:
        lines.append(f"\U0001f517 Internal IP: `{_tg_code(', '.join(private_ips), 160)}`")

    if geo:
        lines.extend(
            [
                f"\U0001f4cd Location: `{_tg_code(_join_geo(geo, ['country', 'countryCode', 'regionName', 'city']))}`",
                f"\U0001f3e2 Network: `{_tg_code(_join_geo(geo, ['isp', 'org']))}`",
                f"\U0001f6f0 ASN: `{_tg_code(_join_geo(geo, ['as', 'asname']))}`",
                f"\U0001f9ed Timezone: `{_tg_code(geo.get('timezone') or 'unknown')}`",
                f"\U0001f6e1 Flags: `{_tg_code(_format_flags(geo))}`",
            ]
        )
    else:
        lines.append("\U0001f4cd Location: `unknown or private IP`")

    lines.extend(
        [
            f"\U0001f4bb Device: `{_tg_code(ua['device'])}`",
            f"\U0001f310 Browser: `{_tg_code(ua['browser'])}`",
            f"\U0001f9fe UA: `{_tg_code(ua['raw'], 160)}`",
        ]
    )
    return "\n".join(lines)


def summarize_user_agent(raw_user_agent):
    raw = _single_line(raw_user_agent, limit=240)
    if parse_user_agent is None or not raw:
        return {"browser": "unknown", "device": "unknown", "raw": raw or "unknown"}

    parsed = parse_user_agent(raw)
    browser = _format_family_version(parsed.browser.family, parsed.browser.version_string)
    os_name = _format_family_version(parsed.os.family, parsed.os.version_string)
    device_bits = []
    if parsed.is_mobile:
        device_bits.append("mobile")
    elif parsed.is_tablet:
        device_bits.append("tablet")
    elif parsed.is_pc:
        device_bits.append("pc")
    elif parsed.is_bot:
        device_bits.append("bot")
    if parsed.device.family and parsed.device.family != "Other":
        device_bits.append(parsed.device.family)
    if os_name != "unknown":
        device_bits.append(os_name)

    return {
        "browser": browser,
        "device": ", ".join(device_bits) or "unknown",
        "raw": raw or "unknown",
    }


def _is_public_ip(ip):
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def _join_geo(data, keys):
    values = []
    for key in keys:
        value = str(data.get(key) or "").strip()
        if value and value not in values:
            values.append(value)
    return ", ".join(values) or "unknown"


def _format_flags(data):
    return ", ".join(
        [
            f"mobile={_yes_no(data.get('mobile'))}",
            f"proxy={_yes_no(data.get('proxy'))}",
            f"hosting={_yes_no(data.get('hosting'))}",
        ]
    )


def _format_family_version(family, version):
    family = (family or "").strip()
    version = (version or "").strip()
    if not family or family == "Other":
        return "unknown"
    return f"{family} {version}".strip()


def _yes_no(value):
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def _tg_code(value, limit=120):
    return _single_line(str(value or "unknown"), limit).replace("`", "'")


def _single_line(value, limit):
    cleaned = " ".join(str(value or "").split())
    return cleaned[:limit] if len(cleaned) > limit else cleaned
