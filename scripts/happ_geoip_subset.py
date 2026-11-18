#!/usr/bin/env python3
"""Build a GeoIPList containing the original BY and RU entries."""

import argparse
from pathlib import Path
from tempfile import NamedTemporaryFile

MAX_INPUT_BYTES = 64 * 1024 * 1024
COUNTRIES = {"BY", "RU"}


def _varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset == len(data):
            raise ValueError("truncated protobuf varint")
        byte = data[offset]
        offset += 1
        if shift == 63 and byte > 1:
            break
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise ValueError("protobuf varint exceeds 64 bits")


def _fields(data):
    offset = 0
    while offset < len(data):
        start = offset
        key, offset = _varint(data, offset)
        number, wire = key >> 3, key & 7
        if not 0 < number < 1 << 29:
            raise ValueError("invalid protobuf field number")
        if wire == 0:
            value, offset = _varint(data, offset)
        else:
            if wire == 2:
                length, offset = _varint(data, offset)
            elif wire == 1:
                length = 8
            elif wire == 5:
                length = 4
            else:
                raise ValueError("unsupported protobuf wire type")
            end = offset + length
            if end > len(data):
                raise ValueError("truncated protobuf field")
            value = data[offset:end]
            offset = end
        yield number, wire, value, start, offset


def _validate_cidr(data):
    ip = None
    prefix = None
    for number, wire, value, _, _ in _fields(data):
        if number == 1:
            if wire != 2 or ip is not None:
                raise ValueError("invalid GeoIP CIDR address field")
            ip = value
        elif number == 2:
            if wire != 0 or prefix is not None:
                raise ValueError("invalid GeoIP CIDR prefix field")
            prefix = value
    # Proto3 omits the prefix field for a /0 network.
    if ip is None or len(ip) not in (4, 16) or (prefix or 0) > len(ip) * 8:
        raise ValueError("invalid GeoIP CIDR")


def _entry_code(data):
    code = None
    has_cidr = False
    for number, wire, value, _, _ in _fields(data):
        if number == 1:
            if wire != 2 or code is not None:
                raise ValueError("invalid GeoIP country code field")
            try:
                code = bytes(value).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("invalid GeoIP country code encoding") from exc
        elif number == 2:
            if wire != 2:
                raise ValueError("invalid GeoIP CIDR field")
            _validate_cidr(value)
            has_cidr = True
    if not code or not has_cidr:
        raise ValueError("GeoIP entry lacks a country code or CIDR")
    return code


def build_subset(data):
    """Select complete entries in source order, keeping their original encoding."""
    data = memoryview(data)
    codes = set()
    selected = []
    for number, wire, value, start, end in _fields(data):
        if number != 1:
            continue
        if wire != 2:
            raise ValueError("invalid GeoIPList entry field")
        code = _entry_code(value)
        if code in codes:
            raise ValueError("duplicate GeoIP country code")
        codes.add(code)
        if code in COUNTRIES:
            selected.append(data[start:end])
    missing = COUNTRIES - codes
    if missing:
        raise ValueError(f"missing GeoIP entries ({', '.join(sorted(missing))})")
    return b"".join(selected)


def _write_output(path, data):
    temporary = None
    try:
        with NamedTemporaryFile(dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(data)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="full Xray geoip.dat")
    parser.add_argument("output", type=Path, help="destination for the BY/RU GeoIPList")
    args = parser.parse_args()
    try:
        with args.input.open("rb") as source:
            data = source.read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            raise ValueError(f"GeoIP input exceeds {MAX_INPUT_BYTES} bytes")
        _write_output(args.output, build_subset(data))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{parser.prog}: {exc}\n")


if __name__ == "__main__":
    main()
