"""Fresh, directionally explicit usage with no imported or rewritten legacy totals."""
import copy
from datetime import UTC, datetime, timedelta, timezone

import pytest

from wg_panel.happ_subscription_usage import read_monthly_usage, read_usage, record_sample

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
    sample(entry, upload=12, download=30, generation='generation-b', at=NOW + timedelta(days=1))
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
    ('version', True), ('version', 3), ('upload', -1), ('download', True),
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
    ('at', datetime.min.replace(tzinfo=UTC)), ('at', datetime.max.replace(tzinfo=UTC)),
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
    assert read_monthly_usage(entry, at=NOW) is None


def legacy_entry(*, started='2026-11-01T00:00:00Z'):
    return {KEY: {'version': 1, 'started_at': started, 'upload': 30, 'download': 250,
                  'checkpoint': {'generation': 'generation-a', 'upload': 130, 'download': 1250}}}


def test_month_boundary_resets_monthly_usage_and_preserves_cumulative_and_history():
    november = datetime(2026, 11, 30, 20, 59, 30, tzinfo=UTC)
    december = november + timedelta(seconds=60)
    entry = {}
    sample(entry, at=november - timedelta(seconds=60))
    sample(entry, upload=130, download=1250, at=november)
    before = copy.deepcopy(entry)
    assert read_monthly_usage(entry, at=december) == {
        'upload': 0, 'download': 0, 'started_at': '2026-11-30T21:00:00Z', 'month': '2026-12'}
    assert entry == before
    sample(entry, upload=140, download=1300, at=december)
    assert read_monthly_usage(entry, at=december) == {
        'upload': 10, 'download': 50, 'started_at': '2026-11-30T21:00:00Z', 'month': '2026-12'}
    assert read_monthly_usage(entry, at=november)['upload'] == 30
    assert read_usage(entry) == {
        'upload': 40, 'download': 300, 'started_at': '2026-11-30T20:58:30Z'}


@pytest.mark.parametrize('offset', [UTC, timezone(timedelta(hours=3)),
                                    timezone(timedelta(hours=-7))])
def test_minsk_calendar_boundary_is_independent_of_input_timezone(offset):
    before = datetime(2026, 11, 30, 20, 59, 59, tzinfo=UTC)
    after = before + timedelta(seconds=1)
    entry = {}
    sample(entry, at=before.astimezone(offset))
    sample(entry, upload=105, download=1010, at=after.astimezone(offset))
    assert set(entry[KEY]['months']) == {'2026-11', '2026-12'}
    assert read_monthly_usage(entry, at=after.astimezone(offset)) == {
        'upload': 5, 'download': 10, 'started_at': '2026-11-30T21:00:00Z', 'month': '2026-12'}


def test_same_minsk_month_v1_is_readable_and_migrates_without_losing_known_usage():
    entry = legacy_entry(started='2026-10-31T21:05:00Z')
    before = copy.deepcopy(entry)
    assert read_monthly_usage(entry, at=NOW) == {
        'upload': 30, 'download': 250, 'started_at': '2026-10-31T21:05:00Z', 'month': '2026-11'}
    assert entry == before
    sample(entry, upload=140, download=1300)
    assert entry[KEY]['version'] == 2
    assert read_monthly_usage(entry, at=NOW) == {
        'upload': 40, 'download': 300, 'started_at': '2026-10-31T21:05:00Z', 'month': '2026-11'}
    assert read_usage(entry) == {'upload': 40, 'download': 300,
                                 'started_at': '2026-10-31T21:05:00Z'}


def test_older_v1_never_guesses_monthly_backfill_or_attributes_untimed_migration_delta():
    entry = legacy_entry(started='2026-10-31T20:59:59Z')
    entry['monthly'] = {'2026-11': {'rx': 999999, 'tx': 888888}}
    assert read_monthly_usage(entry, at=NOW) is None
    sample(entry, upload=150, download=1400)
    assert read_usage(entry) == {'upload': 50, 'download': 400,
                                 'started_at': '2026-10-31T20:59:59Z'}
    assert read_monthly_usage(entry, at=NOW) == {
        'upload': 0, 'download': 0, 'started_at': '2026-11-14T12:00:00Z', 'month': '2026-11'}
    assert read_monthly_usage(entry, at=NOW - timedelta(seconds=1)) is None
    sample(entry, upload=155, download=1410, at=NOW + timedelta(seconds=60))
    assert read_monthly_usage(entry, at=NOW + timedelta(seconds=60))['upload'] == 5
    assert entry['monthly'] == {'2026-11': {'rx': 999999, 'tx': 888888}}


def test_monthly_generation_reset_decrease_and_missing_counters_follow_cumulative_semantics():
    entry = {}
    sample(entry)
    sample(entry, upload=130, download=None)
    sample(entry, upload=None, download=20, generation='generation-b')
    sample(entry, upload=7, download=None, generation='generation-b')
    sample(entry, upload=2, download=5, generation='generation-b')
    usage = read_monthly_usage(entry, at=NOW)
    assert (usage['upload'], usage['download']) == (39, 25)
    assert {key: value for key, value in usage.items() if key != 'month'} == read_usage(entry)
    assert entry[KEY]['checkpoint'] == {'generation': 'generation-b', 'upload': 2, 'download': 5}


def test_missing_counter_across_month_keeps_checkpoint_and_attributes_next_delta_to_sample_month():
    november = datetime(2026, 11, 30, 20, 59, tzinfo=UTC)
    december = november + timedelta(minutes=2)
    entry = {}
    sample(entry, at=november)
    sample(entry, upload=None, download=1200, at=december)
    sample(entry, upload=130, download=None, at=december + timedelta(minutes=1))
    assert read_monthly_usage(entry, at=november)['upload'] == 0
    usage = read_monthly_usage(entry, at=december)
    assert (usage['upload'], usage['download']) == (30, 200)


@pytest.mark.parametrize('upload,download,generation', [
    (140, 1250, 'generation-a'), (130, 1300, 'generation-a'),
    (130, 1250, 'generation-b'), (None, 0, 'generation-a'),
])
def test_out_of_order_changed_sample_is_rejected_without_rewinding_checkpoint(
        upload, download, generation):
    entry = {}
    sample(entry)
    sample(entry, upload=130, download=1250, at=NOW + timedelta(minutes=1))
    before = copy.deepcopy(entry)
    with pytest.raises(ValueError, match='^Invalid subscription usage sample$'):
        sample(entry, upload=upload, download=download, generation=generation, at=NOW)
    assert entry == before


def test_stale_unchanged_poll_is_noop_and_does_not_rewind_last_sample_time():
    entry = {}
    sample(entry)
    sample(entry, upload=130, download=1250, at=NOW + timedelta(minutes=1))
    before = copy.deepcopy(entry)
    sample(entry, upload=130, download=1250, at=NOW)
    sample(entry, upload=None, download=None, at=NOW)
    assert entry == before


def test_v1_sample_before_start_is_rejected_atomically():
    entry = legacy_entry(started='2026-11-15T00:00:00Z')
    before = copy.deepcopy(entry)
    with pytest.raises(ValueError, match='^Invalid subscription usage sample$'):
        sample(entry)
    assert entry == before


@pytest.mark.parametrize('at', [None, '', datetime(2026, 11, 14),
                              datetime(2026, 11, 1, tzinfo=UTC),
                              datetime.max.replace(tzinfo=UTC)])
def test_monthly_read_rejects_unusable_dates_without_mutation(at):
    entry = {}
    sample(entry)
    before = copy.deepcopy(entry)
    assert read_monthly_usage(entry, at=at) is None
    assert entry == before


@pytest.mark.parametrize('field,value', [
    ('sampled_at', None), ('sampled_at', '2026-11-13T00:00:00Z'),
    ('sampled_at', '2026-12-01T00:00:00Z'), ('months', None), ('months', {}),
    ('months', {'2026-13': {'upload': 0, 'download': 0, 'started_at': '2026-11-14T12:00:00Z'}}),
])
def test_malformed_v2_month_metadata_is_unavailable_and_recovers_to_fresh_baseline(field, value):
    entry = {}
    sample(entry)
    entry[KEY][field] = value
    assert read_usage(entry) is None
    assert read_monthly_usage(entry, at=NOW) is None
    sample(entry, upload=10000, download=20000)
    assert read_usage(entry)['upload'] == read_usage(entry)['download'] == 0
    assert read_monthly_usage(entry, at=NOW)['upload'] == 0


@pytest.mark.parametrize('field,value', [
    ('upload', -1), ('download', True), ('upload', 1 << 63), ('download', 1),
    ('started_at', '2026-10-14T12:00:00Z'), ('started_at', '2026-11-15T12:00:00Z'),
    ('started_at', 'private\ntext'), ('extra', 0),
])
def test_monthly_bucket_is_fully_validated_including_cumulative_consistency(field, value):
    entry = {}
    sample(entry)
    entry[KEY]['months']['2026-11'][field] = value
    assert read_usage(entry) is None
    assert read_monthly_usage(entry, at=NOW) is None


def test_overflow_does_not_mutate_month_bucket_or_checkpoint():
    entry = {}
    sample(entry, upload=0, download=0)
    sample(entry, upload=(1 << 63) - 1, download=0)
    before = copy.deepcopy(entry)
    with pytest.raises(ValueError, match='^Invalid subscription usage sample$'):
        sample(entry, upload=1, download=1)
    assert entry == before
    assert read_monthly_usage(entry, at=NOW)['upload'] == (1 << 63) - 1


def test_month_history_is_bounded_and_pruned_month_is_unavailable_without_losing_lifetime_total():
    entry = {}
    for index in range(25):
        at = datetime(2025 + index // 12, 1 + index % 12, 15, tzinfo=UTC)
        sample(entry, upload=100 + index, download=1000 + index * 2, at=at)
    assert len(entry[KEY]['months']) == 24
    assert '2025-01' not in entry[KEY]['months']
    assert read_monthly_usage(entry, at=datetime(2025, 1, 15, tzinfo=UTC)) is None
    assert read_usage(entry)['upload'] == 24
    assert read_usage(entry)['download'] == 48
    usage = read_monthly_usage(entry, at=datetime(2027, 1, 15, tzinfo=UTC))
    usage['upload'] = 9999
    assert read_monthly_usage(entry, at=datetime(2027, 1, 15, tzinfo=UTC))['upload'] == 1
