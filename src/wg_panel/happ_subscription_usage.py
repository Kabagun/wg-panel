"""Directional subscription usage from fresh Xray checkpoints, never legacy history."""
import re
from datetime import UTC, datetime

_KEY = 'happ_subscription_usage'
_MAX_BYTES = (1 << 63) - 1
_ERROR = 'Invalid subscription usage sample'
_GENERATION = re.compile(r'[A-Za-z0-9_.:-]{1,128}')
_STAMP = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'
                    r'(?:\.[0-9]{1,6})?(?:Z|\+00:00)')


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
            or set(tracker) != {'version', 'started_at', 'upload', 'download', 'checkpoint'}
            or type(tracker['version']) is not int or tracker['version'] != 1
            or not _timestamp(tracker['started_at'])
            or not _count(tracker['upload']) or not _count(tracker['download'])):
        return None
    checkpoint = tracker['checkpoint']
    if (not isinstance(checkpoint, dict)
            or set(checkpoint) != {'generation', 'upload', 'download'}
            or not _generation(checkpoint['generation'])
            or not _count(checkpoint['upload']) or not _count(checkpoint['download'])):
        return None
    return tracker


def read_usage(entry):
    """Return validated usage without exposing checkpoints, or None if unavailable."""
    tracker = _tracker(entry)
    if tracker is None:
        return None
    return {key: tracker[key] for key in ('upload', 'download', 'started_at')}


def record_sample(entry, *, generation, upload_bytes, download_bytes, sampled_at):
    """Record explicit raw client uplink/downlink counters in one logical entry.

    The first sample establishes a zero baseline, including recovery from malformed
    tracker state. Later generations and counter decreases contribute from zero.
    A missing counter preserves its checkpoint within the same generation. Invalid
    sample data (including overflow) raises a generic ValueError without mutation.
    Call within the caller's existing traffic transaction; this helper performs no I/O.
    """
    if (not isinstance(entry, dict) or not _generation(generation)
            or any(value is not None and not _count(value)
                   for value in (upload_bytes, download_bytes))
            or not isinstance(sampled_at, datetime) or sampled_at.utcoffset() is None):
        raise ValueError(_ERROR)
    try:
        started_at = sampled_at.astimezone(UTC).isoformat(timespec='seconds').replace('+00:00', 'Z')
    except (ValueError, OverflowError):
        raise ValueError(_ERROR) from None
    previous = _tracker(entry)
    if previous is None:
        tracker = {'version': 1, 'started_at': started_at, 'upload': 0, 'download': 0,
                   'checkpoint': {'generation': generation,
                                  'upload': upload_bytes if upload_bytes is not None else 0,
                                  'download': download_bytes if download_bytes is not None else 0}}
    else:
        same_generation = previous['checkpoint']['generation'] == generation
        tracker = {key: previous[key] for key in ('version', 'started_at', 'upload', 'download')}
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
            checkpoint[field] = raw
        tracker['checkpoint'] = checkpoint
    entry[_KEY] = tracker
