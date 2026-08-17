"""
test_analyzer.py

Testes basicos com pytest para os modulos log_parser e analyzer.

Para rodar a partir da pasta raiz do projeto:
    pytest test_analyzer.py
"""

from log_parser import parse_line, parse_log_file
from analyzer import (
    count_failed_logins_by_ip,
    detect_suspicious_ips,
    get_successful_logins,
    get_failed_logins,
)


SAMPLE_LINES = [
    "2026-08-17 08:30:01 IP=192.168.1.10 LOGIN_FAILED user=admin",
    "2026-08-17 08:30:05 IP=192.168.1.10 LOGIN_FAILED user=admin",
    "2026-08-17 08:31:20 IP=192.168.1.20 LOGIN_SUCCESS user=yuki",
]


def test_parse_line_login_failed():
    event = parse_line(SAMPLE_LINES[0])

    assert event is not None
    assert event["event_type"] == "LOGIN_FAILED"
    assert event["ip"] == "192.168.1.10"


def test_parse_line_login_success():
    event = parse_line(SAMPLE_LINES[2])

    assert event is not None
    assert event["event_type"] == "LOGIN_SUCCESS"
    assert event["user"] == "yuki"


def test_parse_line_invalid_format_returns_none():
    invalid_line = "isso nao e uma linha de log valida"

    assert parse_line(invalid_line) is None


def test_parse_line_invalid_ip_returns_none():
    invalid_line = (
        "2026-08-17 08:30:01 "
        "IP=999.999.999.999 LOGIN_FAILED user=admin"
    )

    assert parse_line(invalid_line) is None


def test_parse_line_invalid_ip_text_returns_none():
    invalid_line = (
        "2026-08-17 08:30:01 "
        "IP=banana LOGIN_FAILED user=admin"
    )

    assert parse_line(invalid_line) is None


def test_parse_log_file_reads_sample(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text("\n".join(SAMPLE_LINES), encoding="utf-8")

    events = parse_log_file(str(log_file))

    assert len(events) == 3


def test_parse_log_file_raises_when_file_missing():
    import pytest as pt

    with pt.raises(FileNotFoundError):
        parse_log_file("arquivo_que_nao_existe.log")


def test_count_failed_logins_by_ip():
    events = [parse_line(line) for line in SAMPLE_LINES]
    events = [event for event in events if event is not None]

    counts = count_failed_logins_by_ip(events)

    assert counts["192.168.1.10"] == 2


def test_get_successful_and_failed_logins():
    events = [parse_line(line) for line in SAMPLE_LINES]
    events = [event for event in events if event is not None]

    success = get_successful_logins(events)
    failed = get_failed_logins(events)

    assert len(success) == 1
    assert len(failed) == 2


def test_detect_suspicious_ips_reaches_threshold():
    failed_counts = {
        "192.168.1.10": 5,
        "192.168.1.20": 2,
    }

    suspicious = detect_suspicious_ips(
        failed_counts,
        threshold=5,
    )

    assert len(suspicious) == 1
    assert suspicious[0]["ip"] == "192.168.1.10"


def test_detect_suspicious_ips_below_threshold_not_flagged():
    failed_counts = {
        "192.168.1.30": 3,
    }

    suspicious = detect_suspicious_ips(
        failed_counts,
        threshold=5,
    )

    assert len(suspicious) == 0
