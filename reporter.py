
"""
reporter.py

Responsável exclusivamente pela apresentação dos resultados
da análise de segurança no terminal.
"""


def print_header(file_path):
    print("=" * 55)
    print("             LOG ANALYZER - BLUE TEAM V2")
    print("=" * 55)
    print()
    print(f"[+] Arquivo analisado: {file_path}")
    print()


def print_summary_counts(summary):
    print("-" * 55)
    print("                 ESTATISTICAS")
    print("-" * 55)

    print(f"[+] Eventos analisados: {summary['total_events']}")
    print(f"[+] Logins bem-sucedidos: {summary['total_success']}")
    print(f"[!] Logins malsucedidos: {summary['total_failed']}")
    print(f"[+] IPs analisados: {summary['total_ips_analisados']}")
    print(f"[!] Linhas invalidas: {summary['invalid_lines']}")
    print()


def print_historical_alerts(suspicious_ips):
    print("-" * 55)
    print("           ALERTAS - CONTAGEM HISTORICA")
    print("-" * 55)

    if not suspicious_ips:
        print("[+] Nenhum IP atingiu o limite historico de falhas.")
        print()
        return

    for item in suspicious_ips:
        print("[!] Possivel atividade suspeita")
        print(f"    IP: {item['ip']}")
        print(f"    Total de falhas: {item['attempts']}")
        print()


def print_temporal_alerts(temporal_alerts):
    print("-" * 55)
    print("             ALERTAS - DETECCAO TEMPORAL")
    print("-" * 55)

    if not temporal_alerts:
        print("[+] Nenhuma atividade suspeita detectada na janela temporal.")
        print()
        return

    for alert in temporal_alerts:
        print("[!] POSSIVEL TENTATIVA DE FORCA BRUTA")
        print(f"    IP: {alert['ip']}")
        print(f"    Tentativas: {alert['attempts']}")
        print(
            f"    Inicio: {alert['window_start'].strftime('%Y-%m-%d %H:%M:%S')}"
        )
        print(
            f"    Final: {alert['window_end'].strftime('%Y-%m-%d %H:%M:%S')}"
        )
        print(f"    Usuarios atingidos: {', '.join(alert['users'])}")
        print()


def print_suspicious_users(suspicious_users):
    print("-" * 55)
    print("             USUARIOS MAIS ATINGIDOS")
    print("-" * 55)

    if not suspicious_users:
        print("[+] Nenhuma tentativa malsucedida encontrada.")
        print()
        return

    for item in suspicious_users:
        print(f"    Usuario: {item['user']}")
        print(f"    Tentativas malsucedidas: {item['attempts']}")
        print()


def print_final_summary(summary, temporal_alerts):
    print("-" * 55)
    print("                 RESUMO FINAL")
    print("-" * 55)

    print(f"IPs suspeitos (historico): {summary['total_ips_suspeitos']}")
    print(f"Alertas temporais: {len(temporal_alerts)}")
    print(f"Linhas invalidas: {summary['invalid_lines']}")

    print()
    print("=" * 55)
    print("          ANALISE CONCLUIDA")
    print("=" * 55)


def print_full_report(
    file_path,
    summary,
    suspicious_ips,
    temporal_alerts,
    suspicious_users
):
    """Exibe o relatório completo da análise."""

    print_header(file_path)
    print_summary_counts(summary)
    print_historical_alerts(suspicious_ips)
    print_temporal_alerts(temporal_alerts)
    print_suspicious_users(suspicious_users)
    print_final_summary(summary, temporal_alerts)
