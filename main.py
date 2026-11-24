
"""
main.py

Ponto de entrada do Log Analyzer.
Coordena a leitura, análise e apresentação dos resultados.
"""

from log_parser import parse_log_file

from analyzer import (
    count_failed_logins_by_ip,
    detect_suspicious_ips,
    detect_brute_force_by_time,
    get_suspicious_users,
    build_summary,
    BRUTE_FORCE_THRESHOLD,
    TIME_WINDOW_SECONDS,
)

from reporter import print_full_report


def get_log_path_from_user():
    """Solicita o caminho do arquivo de log."""
    return input(
        "Digite o caminho do arquivo de log (ex: sample.log): "
    ).strip()


def main():

    log_path = get_log_path_from_user()

    if not log_path:
        print("[ERRO] Nenhum caminho foi informado.")
        return

    try:
        events, invalid_lines = parse_log_file(log_path)

    except FileNotFoundError:
        print(f"[ERRO] Arquivo não encontrado: {log_path}")
        return

    except UnicodeDecodeError:
        print(
            f"[ERRO] Não foi possível ler o arquivo: {log_path}"
        )
        return

    except OSError as error:
        print(f"[ERRO] Falha ao acessar o arquivo: {error}")
        return

    if not events:
        print(
            f"[AVISO] Nenhum evento válido encontrado em: {log_path}"
        )
        print(f"Linhas inválidas: {invalid_lines}")
        return

    # Análise histórica de falhas.
    failed_counts = count_failed_logins_by_ip(events)

    suspicious_ips = detect_suspicious_ips(
        failed_counts,
        BRUTE_FORCE_THRESHOLD
    )

    # Detecção de possíveis ataques por janela temporal.
    temporal_alerts = detect_brute_force_by_time(
        events,
        threshold=BRUTE_FORCE_THRESHOLD,
        window_seconds=TIME_WINDOW_SECONDS
    )

    # Identificação dos usuários mais atingidos.
    suspicious_users = get_suspicious_users(events)

    # Construção das estatísticas.
    summary = build_summary(events, suspicious_ips)

    summary["invalid_lines"] = invalid_lines
    summary["total_alertas_temporais"] = len(temporal_alerts)

    # Apresentação dos resultados.
    print_full_report(
        log_path,
        summary,
        suspicious_ips,
        temporal_alerts,
        suspicious_users
    )


if __name__ == "__main__":
    main()
