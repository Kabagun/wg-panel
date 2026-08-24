import copy
from datetime import date, datetime
from zoneinfo import ZoneInfo

from wg_panel import payments


def test_payment_price_matrix_and_username_validation():
    assert payments.payment_price(1) == 5
    assert payments.payment_price(3) == 5
    assert payments.payment_price(4) == 7
    assert payments.payment_price(5) == 7
    assert payments.payment_price(-1) == 15
    assert payments.payment_price(6) is None
    assert payments.normalize_telegram_username("@Working_User") == "working_user"
    assert payments.normalize_telegram_username("bad-name") == ""
    assert payments.normalize_telegram_username("four") == ""


def test_monthly_anchor_clamps_without_changing_original_day():
    assert payments.effective_due_date(2026, 1, 31) == date(2026, 1, 31)
    assert payments.effective_due_date(2026, 2, 31) == date(2026, 2, 28)
    assert payments.effective_due_date(2028, 2, 31) == date(2028, 2, 29)
    assert payments.effective_due_date(2026, 3, 31) == date(2026, 3, 31)
    assert payments.effective_due_date(2026, 4, 31) == date(2026, 4, 30)
    assert payments.effective_due_date(2026, 2, 30) == date(2026, 2, 28)
    assert payments.effective_due_date(2026, 7, 15) == date(2026, 7, 15)


def memory_store(monkeypatch, users):
    state = copy.deepcopy(users)

    def load():
        return copy.deepcopy(state)

    def mutate(mutator):
        result = mutator(state)
        return result

    monkeypatch.setattr(payments, "load_users", load)
    monkeypatch.setattr(payments, "mutate_users", mutate)
    monkeypatch.setattr(payments, "PAYMENT_ACCOUNT", "5051360900289/1732")
    monkeypatch.setattr(
        payments,
        "PAYMENT_ERIP_PATH",
        "Банковские услуги → Банки / НКФО → Цептер Банк → Пополнение карты",
    )
    return state


def paying_user(day=31, limit=3):
    return {
        "role": "user",
        "approved": True,
        "max_devices": limit,
        "telegram_username": "working_user",
        "payment_enabled": True,
        "payment_day": day,
        "payment_last_notified_month": "",
        "payment_delivery": {"month": "", "parts": []},
    }


def test_due_reminder_sends_two_russian_messages_and_deduplicates(monkeypatch):
    state = memory_store(monkeypatch, {"alice": paying_user()})
    sent = []

    def sender(*args):
        sent.append(args)
        return True

    now = datetime(2026, 2, 28, 9, 0, tzinfo=ZoneInfo("Europe/Minsk"))
    assert payments.process_payment_reminders(now, sender) == [("alice", "sent")]
    assert len(sent) == 2
    assert "Напоминание об оплате VPN" in sent[0][0]
    assert "@working_user" in sent[0][0]
    assert "5 BYN" in sent[0][0]
    assert "28.02.2026" in sent[0][0]
    assert sent[0][3][0][0]["url"] == "https://t.me/working_user"
    assert "Чек об оплате отправлять не нужно" in sent[1][0]
    assert "5051360900289/1732" in sent[1][0]
    assert state["alice"]["payment_last_notified_month"] == "2026-02"
    assert payments.process_payment_reminders(now, sender) == []
    assert len(sent) == 2


def test_multiple_users_are_delivered_as_spaced_sequential_batches(monkeypatch):
    memory_store(
        monkeypatch,
        {"bob": paying_user(day=24), "alice": paying_user(day=24)},
    )
    monkeypatch.setattr(payments, "PAYMENT_USER_DELAY_SECONDS", 60.0)
    timeline = []

    def sender(text, *_args):
        timeline.append(("send", text))
        return True

    now = datetime(2026, 8, 24, 9, 0, tzinfo=ZoneInfo("Europe/Minsk"))
    result = payments.process_payment_reminders(
        now,
        sender,
        sleeper=lambda seconds: timeline.append(("sleep", seconds)),
    )

    assert result == [("alice", "sent"), ("bob", "sent")]
    assert [event[0] for event in timeline] == ["send", "send", "sleep", "send", "send"]
    assert "<code>alice</code>" in timeline[0][1]
    assert "Чек об оплате" in timeline[1][1]
    assert timeline[2] == ("sleep", 60.0)
    assert "<code>bob</code>" in timeline[3][1]
    assert "Чек об оплате" in timeline[4][1]


def test_scheduler_waits_until_nine_and_catches_up_later(monkeypatch):
    memory_store(monkeypatch, {"alice": paying_user(day=15)})
    sent = []
    sender = lambda *args: sent.append(args) or True
    zone = ZoneInfo("Europe/Minsk")
    assert payments.process_payment_reminders(datetime(2026, 8, 15, 8, 59, tzinfo=zone), sender) == []
    assert payments.process_payment_reminders(datetime(2026, 8, 20, 12, 0, tzinfo=zone), sender) == [
        ("alice", "sent")
    ]


def test_partial_failure_retries_only_missing_part(monkeypatch):
    state = memory_store(monkeypatch, {"alice": paying_user(day=15, limit=5)})
    calls = []

    def first_sender(*args):
        calls.append(args)
        return len(calls) == 1

    now = datetime(2026, 8, 15, 9, 0, tzinfo=ZoneInfo("Europe/Minsk"))
    assert payments.process_payment_reminders(now, first_sender) == [("alice", "forward_failed")]
    assert state["alice"]["payment_delivery"] == {"month": "2026-08", "parts": ["summary"]}

    retry_calls = []
    assert payments.process_payment_reminders(
        now, lambda *args: retry_calls.append(args) or True
    ) == [("alice", "sent")]
    assert len(retry_calls) == 1
    assert "Чек об оплате" in retry_calls[0][0]
    assert state["alice"]["payment_last_notified_month"] == "2026-08"


def test_disabled_and_invalid_limit_users_are_skipped(monkeypatch):
    disabled = paying_user()
    disabled["payment_enabled"] = False
    memory_store(
        monkeypatch,
        {"family": disabled, "legacy": paying_user(limit=6), "admin": {"role": "admin"}},
    )
    assert payments.process_payment_reminders(
        datetime(2026, 8, 31, 12, 0, tzinfo=ZoneInfo("Europe/Minsk")),
        lambda *_args: True,
    ) == []
