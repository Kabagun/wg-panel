"""Fresh, directionally explicit usage with no imported or rewritten legacy totals."""
import copy
from datetime import UTC, datetime, timedelta, timezone

import pytest

from wg_panel.happ_subscription_usage import read_usage, record_sample

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
KEY = 'happ_subscription_usage'


def sample(entry, *, upload=100, download=1000, generation='generation-a', at=NOW):
    record_sample(entry, generation=generation, upload_bytes=upload,
                  download_bytes=download, sampled_at=at)


def test_first_observation_is_zero_baseline_not_legacy_monthly_history():
    entry = {'monthly': {'2026-11': {'rx': 999999, 'tx': 888888}},
             'last_rx': 400, 'happ_protocols': {'generation': 'old', 'rx': 20}}
    before = copy.deepcopy(entry)
    sample(entry)
    assert read_usage(entry) == {'upload': 0, 'download': 0, 'started_at': '2026-11-14T12:00:00Z'}
    assert entry[KEY]['checkpoint'] == {'generation': 'generation-a', 'upload': 100, 'download': 1000}
    assert {key: value for key, value in entry.items() if key != KEY} == before


def test_real_upload_download_deltas_and_repeated_poll_have_no_double_count():
    entry = {}
    sample(entry)
    sample(entry, upload=130, download=1250, at=NOW + timedelta(seconds=10))
    assert read_usage(entry) == {'upload': 30, 'download': 250, 'started_at': '2026-11-14T12:00:00Z'}
    before = copy.deepcopy(entry)
    sample(entry, upload=130, download=1250)
    assert entry == before


def test_new_generation_adds_new_process_counters_from_zero_and_keeps_start_date():
    entry = {}
    sample(entry)
    sample(entry, upload=130, download=1250)
    sample(entry, upload=10, download=25, generation='generation-b', at=NOW + timedelta(days=1))
    assert read_usage(entry) == {'upload': 40, 'download': 275, 'started_at': '2026-11-14T12:00:00Z'}
    sample(entry, upload=12, download=30, generation='generation-b')
    assert (read_usage(entry)['upload'], read_usage(entry)['download']) == (42, 280)


def test_counter_decrease_counts_reset_value_independently_per_direction():
    entry = {}
    sample(entry)
    sample(entry, upload=8, download=1200)
    assert (read_usage(entry)['upload'], read_usage(entry)['download']) == (8, 200)
    sample(entry, upload=10, download=15)
    assert (read_usage(entry)['upload'], read_usage(entry)['download']) == (10, 215)


def test_missing_counter_does_not_zero_same_generation_positive_checkpoint():
    entry = {}
    sample(entry)
    sample(entry, upload=None, download=1200)
    assert entry[KEY]['checkpoint']['upload'] == 100
    sample(entry, upload=130, download=None)
    assert entry[KEY]['checkpoint']['download'] == 1200
    sample(entry, upload=None, download=None)
    sample(entry, upload=140, download=1250)
    assert (read_usage(entry)['upload'], read_usage(entry)['download']) == (40, 250)


def test_missing_counter_at_new_generation_uses_zero_not_previous_generation():
    entry = {}
    sample(entry)
    sample(entry, upload=None, download=5, generation='generation-b')
    assert entry[KEY]['checkpoint']['upload'] == 0
    sample(entry, upload=7, download=10, generation='generation-b')
    assert (read_usage(entry)['upload'], read_usage(entry)['download']) == (7, 10)


def test_initial_missing_counters_initialize_zero_checkpoint():
    entry = {}
    sample(entry, upload=None, download=None)
    sample(entry, upload=7, download=10)
    assert (read_usage(entry)['upload'], read_usage(entry)['download']) == (7, 10)


@pytest.mark.parametrize('tracker', [
    None, [], {}, {'version': True},
    {'version': 1, 'started_at': '2026-11-14T12:00:00Z', 'upload': 5, 'download': 6,
     'checkpoint': {'generation': 'g', 'upload': -1, 'download': 6}},
])
def test_malformed_tracker_resets_only_new_tracker(tracker):
    entry = {KEY: tracker, 'monthly': {'2026-11': {'rx': 123, 'tx': 456}}, 'last_tx': 789}
    legacy = copy.deepcopy({key: value for key, value in entry.items() if key != KEY})
    assert read_usage(entry) is None
    sample(entry)
    assert read_usage(entry)['upload'] == read_usage(entry)['download'] == 0
    assert {key: value for key, value in entry.items() if key != KEY} == legacy


@pytest.mark.parametrize('field,value', [
    ('version', True), ('version', 2), ('upload', -1), ('download', True),
    ('upload', '4'), ('download', 1 << 63), ('extra', 'ignored'),
    ('started_at', '2026-11-14'), ('started_at', '2026-02-30T12:00:00Z'),
    ('started_at', '2026-11-14T12:00:00'), ('started_at', '2026-11-14T12:00:00+03:00'),
    ('started_at', '2026-11-14T12:00:00Z\r\nsecret'),
])
def test_read_usage_validates_whole_tracker_and_never_leaks_invalid_state(field, value):
    entry = {}
    sample(entry)
    entry[KEY][field] = value
    assert read_usage(entry) is None
    sample(entry, upload=300, download=400)
    assert read_usage(entry)['upload'] == read_usage(entry)['download'] == 0


@pytest.mark.parametrize('field,value', [
    ('generation', ''), ('generation', 'g\nsecret'), ('generation', 'x' * 129),
    ('generation', None), ('upload', True), ('download', -1), ('extra', 0),
])
def test_read_usage_rejects_malformed_checkpoint(field, value):
    entry = {}
    sample(entry)
    entry[KEY]['checkpoint'][field] = value
    assert read_usage(entry) is None


@pytest.mark.parametrize('argument,value', [
    ('upload', -1), ('download', True), ('upload', 'secret'), ('download', 1 << 63),
    ('generation', ''), ('generation', 'secret\ntext'),
    ('at', datetime(2026, 11, 14)), ('at', '2026-11-14'),
])
def test_invalid_sample_is_generic_and_leaves_all_state_unchanged(argument, value):
    entry = {'monthly': {'2026-11': {'rx': 1, 'tx': 2}}}
    sample(entry)
    before = copy.deepcopy(entry)
    with pytest.raises(ValueError, match='^Invalid subscription usage sample$'):
        sample(entry, **{argument: value})
    assert entry == before


def test_aware_local_sample_is_normalized_to_utc_and_read_returns_a_copy():
    entry = {}
    sample(entry, at=NOW.astimezone(timezone(timedelta(hours=3))))
    usage = read_usage(entry)
    assert usage['started_at'] == '2026-11-14T12:00:00Z'
    usage['upload'] = 99
    assert read_usage(entry)['upload'] == 0
    assert set(usage) == {'upload', 'download', 'started_at'}


def test_bounded_overflow_is_rejected_atomically():
    entry = {}
    sample(entry, upload=0, download=0)
    sample(entry, upload=(1 << 63) - 1, download=0)
    before = copy.deepcopy(entry)
    with pytest.raises(ValueError, match='^Invalid subscription usage sample$'):
        sample(entry, upload=1, download=1)
    assert entry == before


@pytest.mark.parametrize('entry', [None, [], {}, {'monthly': {}}])
def test_absent_or_nonentry_usage_is_unavailable(entry):
    assert read_usage(entry) is None
