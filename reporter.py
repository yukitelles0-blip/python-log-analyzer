"""
reporter.py

Responsavel APENAS por exibir os resultados no terminal.
Nenhuma logica de analise deve ficar aqui, so formatacao e print.

Separar isso do analyzer.py facilita, por exemplo, trocar o terminal
por um relatorio em arquivo ou HTML no futuro, sem mexer na logica.
"""


def print_header(file_path):
    print("=" * 40)
    print("LOG ANALYZER - BLUE TEAM")
    print("=" * 40)
    print()
    print(f"[+] Arquivo analisado: {file_path}")
    print()


def print_summary_counts(summary):
    print(f"[+] Eventos analisados: {summary['total_events']}")
    print()
    print(f"[+] Login bem-sucedido: {summary['total_success']}")
    print(f"[!] Login malsucedido: {summary['total_failed']}")
    print()


def print_alerts(suspicious_ips):
    print("-" * 40)
    print("      ALERTAS")
    print("-" * 40)
    print()

    if not suspicious_ips:
        print("[+] Nenhuma atividade suspeita encontrada.")
        print()
        return

    for item in suspicious_ips:
        print("[!] Possivel atividade suspeita")
        print(f"IP: {item['ip']}")
        print(f"Tentativas: {item['attempts']}")
        print()


def print_final_summary(summary):
    print("-" * 40)
    print("      RESUMO")
    print("-" * 40)
    print()
    print(f"IPs analisados: {summary['total_ips_analisados']}")
    print(f"IPs suspeitos: {summary['total_ips_suspeitos']}")
    print()
    print("=" * 40)


def print_full_report(file_path, summary, suspicious_ips):
    """Funcao de conveniencia que chama todos os prints na ordem certa."""
    print_header(file_path)
    print_summary_counts(summary)
    print_alerts(suspicious_ips)
    print_final_summary(summary)
