import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/happ_geoip_subset.py"
SPEC = importlib.util.spec_from_file_location("happ_geoip_subset", SCRIPT)
subset = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(subset)


def message(number, payload):
    assert number < 16 and len(payload) < 128
    return bytes(((number << 3) | 2, len(payload))) + payload


CIDR = message(2, message(1, b"\xc0\x00\x02\x00") + b"\x10\x18")
CIDR_V6 = message(2, message(1, bytes.fromhex("20010db8000000000000000000000000")) + b"\x10\x20")


def entry(code, more=b""):
    return message(1, message(1, code) + CIDR + more)


def test_preserves_both_complete_entries_in_source_order():
    ru = entry(b"RU", CIDR_V6 + b"\x30\x07")
    by = entry(b"BY", message(2, message(1, b"\x00" * 4)))
    source = message(8, b"top-level extension") + ru + entry(b"PRIVATE") + by
    assert subset.build_subset(source) == ru + by


@pytest.mark.parametrize(
    ("data", "error"),
    [
        (entry(b"BY"), "missing GeoIP entries.*RU"),
        (entry(b"RU"), "missing GeoIP entries.*BY"),
        (entry(b"BY") * 2 + entry(b"RU"), "duplicate GeoIP country code"),
        (entry(b"RU") * 2 + entry(b"BY"), "duplicate GeoIP country code"),
        (entry(b"BY", message(1, b"RU")), "invalid GeoIP country code field"),
        (message(1, message(1, b"BY")), "lacks a country code or CIDR"),
        (message(1, CIDR), "lacks a country code or CIDR"),
        (entry(b"\xff"), "invalid GeoIP country code encoding"),
        (entry(b"BY", message(2, b"\x10\x18")), "invalid GeoIP CIDR"),
        (entry(b"BY", message(2, message(1, b"\x00" * 4) + b"\x10\x21")), "invalid GeoIP CIDR"),
        (entry(b"BY")[:-1], "truncated protobuf field"),
        (b"\x0a\x80", "truncated protobuf varint"),
        (b"\x0a" + b"\xff" * 10, "protobuf varint exceeds 64 bits"),
        (b"\x08\x01", "invalid GeoIPList entry field"),
    ],
)
def test_rejects_invalid_geoip_list(data, error):
    with pytest.raises(ValueError, match=error):
        subset.build_subset(data)


def test_cli_rejects_oversize_input_and_preserves_destination(tmp_path, monkeypatch, capsys):
    source = tmp_path / "full.dat"
    destination = tmp_path / "subset.dat"
    data = entry(b"BY") + entry(b"RU")
    source.write_bytes(data)
    destination.write_bytes(b"previous")
    monkeypatch.setattr(subset, "MAX_INPUT_BYTES", len(data) - 1)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), str(source), str(destination)])

    with pytest.raises(SystemExit) as failure:
        subset.main()
    assert failure.value.code == 1
    assert "GeoIP input exceeds" in capsys.readouterr().err
    assert destination.read_bytes() == b"previous"

    monkeypatch.setattr(subset, "MAX_INPUT_BYTES", len(data))
    subset.main()
    assert destination.read_bytes() == data
