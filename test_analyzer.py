
"""
test_analyzer.py

Testes automatizados do Log Analyzer V2.
Para executar na raiz do projeto:
    pytest -v
"""

from datetime import datetime

import pytest

from log_parser import parse_line, parse_log_file
from analyzer import (
    count_failed_logins_by_ip,
    detect_suspicious_ips,
    detect_brute_force_by_time,
    get_successful_logins,
    get_failed_logins,
    get_suspicious_users,
)


SAMPLE_LINES = [
    "2026-08-17 08:30:01 IP=192.168.1.10 LOGIN_FAILED user=admin",
    "2026-08-17 08:30:05 IP=192.168.1.10 LOGIN_FAILED user=admin",
    "2026-08-17 08:31:20 IP=192.168.1.20 LOGIN_SUCCESS user=yuki",
]


def create_event(timestamp, ip, event_type, user):
    """Cria um evento estruturado para os testes."""
    return {
        "timestamp": datetime.strptime(
            timestamp, "%Y-%m-%d %H:%M:%S"
        ),
        "ip": ip,
        "event_type": event_type,
        "user": user,
    }


# TESTES DO PARSER


def test_parse_line_login_failed():
    event = parse_line(SAMPLE_LINES[0])

    assert event is not None
    assert event["event_type"] == "LOGIN_FAILED"
    assert event["ip"] == "192.168.1.10"
    assert isinstance(event["timestamp"], datetime)


def test_parse_line_login_success():
    event = parse_line(SAMPLE_LINES[2])

    assert event is not None
    assert event["event_type"] == "LOGIN_SUCCESS"
    assert event["user"] == "yuki"


def test_parse_line_invalid_format_returns_none():
    assert parse_line("linha invalida") is None


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


def test_parse_line_invalid_date_returns_none():
    invalid_line = (
        "2026-15-40 08:30:01 "
        "IP=192.168.1.10 LOGIN_FAILED user=admin"
    )

    assert parse_line(invalid_line) is None


def test_parse_log_file_reads_sample(tmp_path):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        "\n".join(SAMPLE_LINES),
        encoding="utf-8"
    )

    events, invalid_lines = parse_log_file(str(log_file))

    assert len(events) == 3
    assert invalid_lines == 0


def test_parse_log_file_counts_invalid_lines(tmp_path):
    log_file = tmp_path / "test.log"

    content = "\n".join([
        SAMPLE_LINES[0],
        "linha invalida",
        SAMPLE_LINES[1],
        "",
    ])

    log_file.write_text(content, encoding="utf-8")

    events, invalid_lines = parse_log_file(str(log_file))

    assert len(events) == 2
    assert invalid_lines == 1


def test_parse_log_file_raises_when_file_missing():
    with pytest.raises(FileNotFoundError):
        parse_log_file("arquivo_que_nao_existe.log")


# TESTES DO ANALYZER


def test_count_failed_logins_by_ip():
    events = [
        parse_line(line)
        for line in SAMPLE_LINES
    ]

    counts = count_failed_logins_by_ip(events)

    assert counts["192.168.1.10"] == 2


def test_get_successful_and_failed_logins():
    events = [
        parse_line(line)
        for line in SAMPLE_LINES
    ]

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


def test_detect_suspicious_ips_below_threshold():
    failed_counts = {
        "192.168.1.30": 3,
    }

    suspicious = detect_suspicious_ips(
        failed_counts,
        threshold=5,
    )

    assert len(suspicious) == 0


# TESTES DA DETECCAO TEMPORAL


def test_detect_brute_force_within_60_seconds():
    events = [
        create_event(
            f"2026-08-17 08:30:{second:02d}",
            "192.168.1.10",
            "LOGIN_FAILED",
            "admin"
        )
        for second in [1, 10, 18, 25, 40]
    ]

    alerts = detect_brute_force_by_time(events)

    assert len(alerts) == 1
    assert alerts[0]["ip"] == "192.168.1.10"
    assert alerts[0]["attempts"] == 5


def test_no_alert_when_failures_are_outside_window():
    events = [
        create_event(
            f"2026-08-17 08:{minute:02d}:{second:02d}",
            "192.168.1.10",
            "LOGIN_FAILED",
            "admin"
        )
        for minute, second in [
            (30, 0),
            (31, 1),
            (32, 2),
            (33, 3),
            (34, 4),
        ]
    ]

    alerts = detect_brute_force_by_time(events)

    assert len(alerts) == 0


def test_no_alert_with_only_four_failures():
    events = [
        create_event(
            f"2026-08-17 08:30:{second:02d}",
            "192.168.1.10",
            "LOGIN_FAILED",
            "admin"
        )
        for second in [1, 10, 20, 30]
    ]

    alerts = detect_brute_force_by_time(events)

    assert len(alerts) == 0


def test_temporal_detection_separates_different_ips():
    events = []

    for ip in ["192.168.1.10", "192.168.1.20"]:
        for second in [1, 10, 20, 30, 40]:
            events.append(
                create_event(
                    f"2026-08-17 08:30:{second:02d}",
                    ip,
                    "LOGIN_FAILED",
                    "admin"
                )
            )

    alerts = detect_brute_force_by_time(events)

    assert len(alerts) == 2
    assert {alert["ip"] for alert in alerts} == {
        "192.168.1.10",
        "192.168.1.20"
    }


def test_temporal_detection_handles_unsorted_events():
    events = [
        create_event(
            f"2026-08-17 08:30:{second:02d}",
            "192.168.1.10",
            "LOGIN_FAILED",
            "admin"
        )
        for second in [40, 1, 25, 10, 18]
    ]

    alerts = detect_brute_force_by_time(events)

    assert len(alerts) == 1
    assert alerts[0]["attempts"] == 5


def test_temporal_detection_ignores_successful_logins():
    events = [
        create_event(
            f"2026-08-17 08:30:{second:02d}",
            "192.168.1.10",
            "LOGIN_FAILED",
            "admin"
        )
        for second in [1, 10, 20, 30]
    ]

    events.append(
        create_event(
            "2026-08-17 08:30:35",
            "192.168.1.10",
            "LOGIN_SUCCESS",
            "admin"
        )
    )

    alerts = detect_brute_force_by_time(events)

    assert len(alerts) == 0


# TESTES DE ANALISE DE USUARIOS


def test_get_suspicious_users():
    events = [
        create_event(
            "2026-08-17 08:30:01",
            "192.168.1.10",
            "LOGIN_FAILED",
            "admin"
        ),
        create_event(
            "2026-08-17 08:30:05",
            "192.168.1.20",
            "LOGIN_FAILED",
            "admin"
        ),
        create_event(
            "2026-08-17 08:30:10",
            "192.168.1.30",
            "LOGIN_FAILED",
            "root"
        ),
    ]

    users = get_suspicious_users(events)

    assert users[0]["user"] == "admin"
    assert users[0]["attempts"] == 2
    assert users[1]["user"] == "root"
    assert users[1]["attempts"] == 1
