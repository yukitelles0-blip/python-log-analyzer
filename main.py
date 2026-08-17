"""
main.py

Ponto de entrada do programa.
Aqui juntamos os modulos log_parser, analyzer e reporter.

Para executar (a partir da pasta raiz do projeto):
    python main.py
"""

import sys
import os

# # Garante que o Python encontra os outros módulos do projeto.
# Os arquivos estão na mesma pasta que o main.py.
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from log_parser import parse_log_file
from analyzer import (
    count_failed_logins_by_ip,
    detect_suspicious_ips,
    build_summary,
    BRUTE_FORCE_THRESHOLD,
)
from reporter import print_full_report


def get_log_path_from_user():
    """Pede ao usuario o caminho do arquivo de log pelo terminal."""
    path = input("Digite o caminho do arquivo de log (ex: sample.log): ").strip()
    return path


def main():
    log_path = get_log_path_from_user()

    try:
        events = parse_log_file(log_path)
    except FileNotFoundError:
        print(f"[ERRO] Arquivo nao encontrado: {log_path}")
        return
    except UnicodeDecodeError:
        print(f"[ERRO] Nao foi possivel ler o arquivo (formato invalido): {log_path}")
        return
    except Exception as e:
        # Captura generica por seguranca, para o programa nunca "quebrar feio"
        print(f"[ERRO] Ocorreu um erro inesperado ao ler o arquivo: {e}")
        return

    if not events:
        print(f"[AVISO] Nenhum evento valido foi encontrado em: {log_path}")
        return

    failed_counts = count_failed_logins_by_ip(events)
    suspicious_ips = detect_suspicious_ips(failed_counts, BRUTE_FORCE_THRESHOLD)
    summary = build_summary(events, suspicious_ips)

    print_full_report(log_path, summary, suspicious_ips)


if __name__ == "__main__":
    main()
