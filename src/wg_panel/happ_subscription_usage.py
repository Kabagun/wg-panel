"""Directional subscription usage from fresh Xray checkpoints, never legacy history."""
import re
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

_KEY = 'happ_subscription_usage'
_MAX_BYTES = (1 << 63) - 1
_ERROR = 'Invalid subscription usage sample'
_GENERATION = re.compile(r'[A-Za-z0-9_.:-]{1,128}')
_STAMP = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'
                    r'(?:\.[0-9]{1,6})?(?:Z|\+00:00)')
_MONTH = re.compile(r'[0-9]{4}-(?:0[1-9]|1[0-2])')
_MINSK = ZoneInfo('Europe/Minsk')
_MAX_MONTHS = 24


def _count(value):
    return type(value) is int and 0 <= value <= _MAX_BYTES


def _generation(value):
    return isinstance(value, str) and bool(_GENERATION.fullmatch(value))


def _timestamp(value):
    if not isinstance(value, str) or not _STAMP.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(value)
        return True
    except ValueError:
        return False


def _tracker(entry):
    tracker = entry.get(_KEY) if isinstance(entry, dict) else None
    if (not isinstance(tracker, dict)
            or type(tracker.get('version')) is not int or tracker['version'] not in (1, 2)
            or set(tracker) != ({'version', 'started_at', 'upload', 'download', 'checkpoint'}
                                | ({'sampled_at', 'months'} if tracker['version'] == 2 else set()))
            or not _timestamp(tracker['started_at'])
            or not _count(tracker['upload']) or not _count(tracker['download'])):
        return None
    checkpoint = tracker['checkpoint']
    if (not isinstance(checkpoint, dict)
            or set(checkpoint) != {'generation', 'upload', 'download'}
            or not _generation(checkpoint['generation'])
            or not _count(checkpoint['upload']) or not _count(checkpoint['download'])):
        return None
    if tracker['version'] == 2 and not _valid_months(tracker):
        return None
    return tracker


def _month(at):
    local = at.astimezone(_MINSK)
    return f'{local.year:04d}-{local.month:02d}'


def _stamp(at):
    return at.astimezone(UTC).isoformat(timespec='seconds').replace('+00:00', 'Z')


def _month_start(at):
    return _stamp(at.astimezone(_MINSK).replace(day=1, hour=0, minute=0, second=0, microsecond=0))


def _valid_months(tracker):
    if not _timestamp(tracker['sampled_at']):
        return False
    sampled = datetime.fromisoformat(tracker['sampled_at'])
    started = datetime.fromisoformat(tracker['started_at'])
    months = tracker['months']
    if (started > sampled or not isinstance(months, dict) or not 1 <= len(months) <= _MAX_MONTHS):
        return False
    try:
        current = _month(sampled)
        if current not in months:
            return False
        totals = {'upload': 0, 'download': 0}
        for month, bucket in months.items():
            if (not isinstance(month, str) or not _MONTH.fullmatch(month)
                    or month.startswith('0000-') or month > current
                    or not isinstance(bucket, dict)
                    or set(bucket) != {'upload', 'download', 'started_at'}
                    or not _timestamp(bucket['started_at'])
                    or not _count(bucket['upload']) or not _count(bucket['download'])):
                return False
            bucket_start = datetime.fromisoformat(bucket['started_at'])
            if not started <= bucket_start <= sampled or _month(bucket_start) != month:
                return False
            for field in totals:
                totals[field] += bucket[field]
        return all(totals[field] <= tracker[field] for field in totals)
    except (ValueError, OverflowError):
        return False


def read_usage(entry):
    """Return validated usage without exposing checkpoints, or None if unavailable."""
    tracker = _tracker(entry)
    if tracker is None:
        return None
    return {key: tracker[key] for key in ('upload', 'download', 'started_at')}


def read_monthly_usage(entry, *, at):
    """Read a Minsk calendar month, or None when its directional usage is uncertain.

    Future months after the last checkpoint have zero observed usage. Unretained
    historical months are unavailable. A v1 total is usable only in its start month.
    The returned started_at remains UTC and denotes the beginning of known coverage.
    """
    tracker = _tracker(entry)
    if (tracker is None or not isinstance(at, datetime) or at.utcoffset() is None):
        return None
    try:
        month = _month(at)
        if at < datetime.fromisoformat(tracker['started_at']):
            return None
        if tracker['version'] == 1:
            if month != _month(datetime.fromisoformat(tracker['started_at'])):
                return None
            bucket = read_usage(entry)
        elif month in tracker['months']:
            bucket = tracker['months'][month]
            if at < datetime.fromisoformat(bucket['started_at']):
                return None
        elif month > _month(datetime.fromisoformat(tracker['sampled_at'])):
            bucket = {'upload': 0, 'download': 0, 'started_at': _month_start(at)}
        else:
            return None
        return {**bucket, 'month': month}
    except (ValueError, OverflowError):
        return None


def record_sample(entry, *, generation, upload_bytes, download_bytes, sampled_at):
    """Record explicit raw client uplink/downlink counters in one logical entry.

    The first sample establishes a zero baseline, including recovery from malformed
    tracker state. Later generations and counter decreases contribute from zero.
    A missing counter preserves its checkpoint within the same generation. Invalid
    sample data (including overflow) raises a generic ValueError without mutation.
    Each delta belongs to the sample's Minsk month, with up to one polling interval
    of boundary uncertainty. Keep the latest 24 observed months. Old v1 lifetime
    totals seed a month only when their start is within that same month. Otherwise
    migration starts a zero monthly baseline: its untimed v1 delta is cumulative only.
    Call within the caller's existing traffic transaction; this helper performs no I/O.
    """
    if (not isinstance(entry, dict) or not _generation(generation)
            or any(value is not None and not _count(value)
                   for value in (upload_bytes, download_bytes))
            or not isinstance(sampled_at, datetime) or sampled_at.utcoffset() is None):
        raise ValueError(_ERROR)
    try:
        started_at = _stamp(sampled_at)
        month = _month(sampled_at)
        month_start = _month_start(sampled_at)
    except (ValueError, OverflowError):
        raise ValueError(_ERROR) from None
    previous = _tracker(entry)
    if previous is None:
        tracker = {'version': 2, 'started_at': started_at, 'upload': 0, 'download': 0,
                   'checkpoint': {'generation': generation,
                                  'upload': upload_bytes if upload_bytes is not None else 0,
                                  'download': download_bytes if download_bytes is not None else 0},
                   'sampled_at': started_at,
                   'months': {month: {'upload': 0, 'download': 0, 'started_at': started_at}}}
    else:
        same_generation = previous['checkpoint']['generation'] == generation
        if sampled_at < datetime.fromisoformat(previous.get('sampled_at', previous['started_at'])):
            if (previous['version'] == 2 and same_generation
                    and all(raw is None or raw == previous['checkpoint'][field]
                            for field, raw in (('upload', upload_bytes),
                                               ('download', download_bytes)))):
                return
            raise ValueError(_ERROR)
        tracker = {key: previous[key] for key in ('started_at', 'upload', 'download')}
        tracker.update(version=2, sampled_at=started_at)
        months = ({key: dict(value) for key, value in previous['months'].items()}
                  if previous['version'] == 2 else {})
        attributable = (previous['version'] == 2
                        or _month(datetime.fromisoformat(previous['started_at'])) == month)
        if previous['version'] == 1 and attributable:
            months[month] = read_usage(entry)
        if month not in months:
            months[month] = {'upload': 0, 'download': 0,
                             'started_at': (month_start if previous['version'] == 2
                                            else started_at)}
        checkpoint = {'generation': generation}
        for field, raw in (('upload', upload_bytes), ('download', download_bytes)):
            old = previous['checkpoint'][field] if same_generation else 0
            if raw is None:
                checkpoint[field] = old
                continue
            delta = raw - old if raw >= old else raw
            total = tracker[field] + delta
            if not _count(total):
                raise ValueError(_ERROR)
            tracker[field] = total
            monthly_total = months[month][field] + (delta if attributable else 0)
            if not _count(monthly_total):
                raise ValueError(_ERROR)
            months[month][field] = monthly_total
            checkpoint[field] = raw
        tracker['checkpoint'] = checkpoint
        tracker['months'] = {key: months[key] for key in sorted(months)[-_MAX_MONTHS:]}
    if _tracker({_KEY: tracker}) is None:
        raise ValueError(_ERROR)
    entry[_KEY] = tracker
