"""
analyzer.py

Responsavel por analisar a lista de eventos e gerar as informacoes
que o Blue Team quer ver: contagem de falhas por IP, possiveis
IPs suspeitos, resumo geral, etc.

Este modulo NAO imprime nada na tela — ele so calcula e retorna dados.
Quem imprime e o reporter.py.
"""

# Limite de tentativas malsucedidas para considerar "possivel forca bruta"
BRUTE_FORCE_THRESHOLD = 5


def count_failed_logins_by_ip(events):
    """
    Recebe a lista de eventos e retorna um dicionario:
    { "192.168.1.10": 7, "192.168.1.30": 2, ... }
    contando quantos LOGIN_FAILED cada IP teve.
    """
    failed_counts = {}

    for event in events:
        if event["event_type"] == "LOGIN_FAILED":
            ip = event["ip"]
            failed_counts[ip] = failed_counts.get(ip, 0) + 1

    return failed_counts


def get_successful_logins(events):
    """Retorna a lista de eventos do tipo LOGIN_SUCCESS."""
    return [e for e in events if e["event_type"] == "LOGIN_SUCCESS"]


def get_failed_logins(events):
    """Retorna a lista de eventos do tipo LOGIN_FAILED."""
    return [e for e in events if e["event_type"] == "LOGIN_FAILED"]


def detect_suspicious_ips(failed_counts, threshold=BRUTE_FORCE_THRESHOLD):
    """
    Recebe o dicionario de falhas por IP e retorna uma lista de
    dicionarios com os IPs que atingiram ou ultrapassaram o limite:

    [{"ip": "192.168.1.10", "attempts": 7}, ...]

    IMPORTANTE: isso e apenas um indicio, nao uma prova de ataque.
    Por isso usamos o termo "possivel" em todo o projeto.
    """
    suspicious = []

    for ip, attempts in failed_counts.items():
        if attempts >= threshold:
            suspicious.append({"ip": ip, "attempts": attempts})

    return suspicious


def build_summary(events, suspicious_ips):
    """
    Monta um dicionario com o resumo geral da analise,
    usado depois pelo reporter.py para exibir os resultados.
    """
    total_events = len(events)
    total_success = len(get_successful_logins(events))
    total_failed = len(get_failed_logins(events))
    total_ips_analisados = len({e["ip"] for e in events})

    summary = {
        "total_events": total_events,
        "total_success": total_success,
        "total_failed": total_failed,
        "total_ips_analisados": total_ips_analisados,
        "total_ips_suspeitos": len(suspicious_ips),
    }

    return summary
