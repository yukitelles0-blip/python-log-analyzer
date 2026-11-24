
import main


def prepare_main(monkeypatch, tmp_path):
    """Prepara o ambiente para testar o fluxo principal."""

    events = [{"event_type": "LOGIN_FAILED"}]

    summary = {
        "total_events": 1,
        "successful_logins": 0,
        "failed_logins": 1
    }

    monkeypatch.setattr(
        main,
        "get_log_path_from_user",
        lambda: "sample.log"
    )

    monkeypatch.setattr(
        main,
        "parse_log_file",
        lambda path: (events, 0)
    )

    monkeypatch.setattr(
        main,
        "count_failed_logins_by_ip",
        lambda events: {}
    )

    monkeypatch.setattr(
        main,
        "detect_suspicious_ips",
        lambda counts, threshold: []
    )

    monkeypatch.setattr(
        main,
        "detect_brute_force_by_time",
        lambda events, threshold, window_seconds: []
    )

    monkeypatch.setattr(
        main,
        "get_suspicious_users",
        lambda events: []
    )

    monkeypatch.setattr(
        main,
        "build_summary",
        lambda events, ips: summary.copy()
    )

    monkeypatch.setattr(
        main,
        "print_full_report",
        lambda *args: None
    )

    return events, summary


def test_main_generates_json_and_csv(monkeypatch, tmp_path, capsys):
    events, summary = prepare_main(monkeypatch, tmp_path)

    export_calls = []

    def fake_export(*args):
        export_calls.append(args)
        return (
            tmp_path / "security_report.json",
            tmp_path / "security_report.csv"
        )

    monkeypatch.setattr(main, "export_reports", fake_export)

    main.main()

    assert len(export_calls) == 1
    assert export_calls[0][0] == "sample.log"
    assert export_calls[0][1]["invalid_lines"] == 0

    output = capsys.readouterr().out

    assert "[EXPORTAÇÃO CONCLUÍDA]" in output
    assert "security_report.json" in output
    assert "security_report.csv" in output


def test_main_handles_export_error(monkeypatch, tmp_path, capsys):
    prepare_main(monkeypatch, tmp_path)

    def fake_export(*args):
        raise OSError("Erro de gravação")

    monkeypatch.setattr(main, "export_reports", fake_export)

    main.main()

    output = capsys.readouterr().out

    assert "[ERRO] Não foi possível exportar" in output
    assert "Erro de gravação" in output


def test_main_does_not_export_without_valid_events(
    monkeypatch, tmp_path, capsys
):
    prepare_main(monkeypatch, tmp_path)

    monkeypatch.setattr(
        main,
        "parse_log_file",
        lambda path: ([], 3)
    )

    def unexpected_export(*args):
        raise AssertionError("A exportação não deveria ser executada")

    monkeypatch.setattr(main, "export_reports", unexpected_export)

    main.main()

    output = capsys.readouterr().out

    assert "Nenhum evento válido encontrado" in output
    assert "Linhas inválidas: 3" in output
