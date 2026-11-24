
import csv
import json
from datetime import datetime

from exporter import (
    build_report,
    export_json,
    export_csv,
    export_reports
)


def sample_data():
    summary = {
        "total_events": 10,
        "successful_logins": 4,
        "failed_logins": 6
    }

    suspicious_ips = [
        {"ip": "192.168.1.10", "attempts": 6}
    ]

    temporal_alerts = [
        {
            "ip": "192.168.1.10",
            "attempts": 6,
            "window_start": datetime(2026, 11, 24, 8, 30, 0),
            "window_end": datetime(2026, 11, 24, 8, 30, 40),
            "users": ["admin"]
        }
    ]

    suspicious_users = [
        {"user": "admin", "attempts": 6}
    ]

    return summary, suspicious_ips, temporal_alerts, suspicious_users


def test_build_report_contains_all_sections():
    summary, ips, alerts, users = sample_data()

    report = build_report(
        "sample.log", summary, ips, alerts, users
    )

    assert "resumo" in report
    assert "alertas_historicos" in report
    assert "alertas_temporais" in report
    assert "usuarios_suspeitos" in report


def test_export_json_creates_valid_file(tmp_path):
    summary, ips, alerts, users = sample_data()

    report = build_report(
        "sample.log", summary, ips, alerts, users
    )

    file_path = export_json(report, tmp_path)

    assert file_path.exists()

    with file_path.open(encoding="utf-8") as file:
        data = json.load(file)

    assert data["resumo"]["total_events"] == 10
    assert data["alertas_temporais"][0]["ip"] == "192.168.1.10"


def test_export_json_converts_dates(tmp_path):
    summary, ips, alerts, users = sample_data()

    report = build_report(
        "sample.log", summary, ips, alerts, users
    )

    file_path = export_json(report, tmp_path)

    with file_path.open(encoding="utf-8") as file:
        data = json.load(file)

    assert isinstance(
        data["alertas_temporais"][0]["window_start"], str
    )


def test_export_csv_creates_valid_file(tmp_path):
    summary, ips, alerts, users = sample_data()

    report = build_report(
        "sample.log", summary, ips, alerts, users
    )

    file_path = export_csv(report, tmp_path)

    assert file_path.exists()

    with file_path.open(encoding="utf-8-sig", newline="") as file:
        rows = list(csv.reader(file, delimiter=";"))

    assert rows[0] == ["categoria", "detalhes"]
    assert any(row[0] == "resumo" for row in rows[1:])
    assert any(row[0] == "alertas_temporais" for row in rows[1:])


def test_export_reports_creates_both_files(tmp_path):
    summary, ips, alerts, users = sample_data()

    json_file, csv_file = export_reports(
        "sample.log",
        summary,
        ips,
        alerts,
        users,
        tmp_path
    )

    assert json_file.exists()
    assert csv_file.exists()
